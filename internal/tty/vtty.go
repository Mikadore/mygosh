package tty

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
	"github.com/rotisserie/eris"
)

type VTTY struct {
	tty     *os.File
	winsize *pty.Winsize
}

// CreateVTTY currently uses pty.Start as the small first step: it creates a
// pseudo-terminal, wires the command's stdin/stdout/stderr to the slave side,
// starts the process in a new session, and makes that slave the process'
// controlling terminal.
//
// Once sessions are user/auth aware, prefer pty.StartWithAttrs(cmd, size, attrs)
// so the VTTY is created with explicit session state instead of inheriting
// process defaults:
//   - size (*pty.Winsize): terminal geometry to install before the child starts.
//     Rows and Cols are the terminal cell dimensions; X and Y are optional pixel
//     dimensions and are usually left zero unless the client reports them.
//   - attrs.Setsid: create a new session for the child. Interactive programs
//     expect this so job control and the controlling terminal belong to the
//     virtual terminal session instead of this server process.
//   - attrs.Setctty: make the PTY slave the child's controlling terminal.
//     creack/pty's StartWithSize sets this with Setsid for normal shells.
//   - attrs.Credential: run the child as the authenticated user's UID/GID and
//     supplementary groups when the server is allowed to switch identity.
//   - attrs.Chroot, Cloneflags, Unshareflags, UidMappings, GidMappings, and
//     AmbientCaps: optional isolation/namespace/capability controls for future
//     sandboxing; set them only from trusted policy, not directly from clients.
//
// Non-SysProcAttr process state should stay on exec.Cmd: set cmd.Dir for the
// working directory and cmd.Env for the authenticated session environment
// before starting the process.
func CreateVTTY(size Size, cmd *exec.Cmd) (*VTTY, error) {
	var vtty VTTY

	// "Starts the process in a new session and sets the controlling terminal."
	winsize := &pty.Winsize{Cols: uint16(size.Width), Rows: uint16(size.Height)}
	tty, err := pty.StartWithSize(cmd, winsize)
	if err != nil {
		return &vtty, eris.Wrapf(err, "Failed to create VTTY with command %v", cmd.Path)
	}

	vtty.tty = tty
	vtty.winsize = winsize
	return &vtty, nil
}

func (t *VTTY) Read(p []byte) (int, error) {
	return t.tty.Read(p)
}

func (t *VTTY) Write(p []byte) (int, error) {
	return t.tty.Write(p)
}

func (t *VTTY) Resize(size Size) error {
	t.winsize.Cols = uint16(size.Width)
	t.winsize.Rows = uint16(size.Height)

	return eris.Wrap(pty.Setsize(t.tty, t.winsize), "Failed to resize VTTY")
}

func (t *VTTY) Close() error {
	return t.tty.Close()
}

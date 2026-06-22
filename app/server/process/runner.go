//go:build linux || darwin || freebsd || openbsd || netbsd

package process

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/Mikadore/mygosh/lib/command"
	"github.com/creack/pty"
	"github.com/rotisserie/eris"
	"golang.org/x/sys/unix"
)

type Runner struct{}

func (Runner) Start(ctx context.Context, spec Spec) (command.RunningProcess, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec = spec.clone()
	if err := spec.validate(); err != nil {
		return nil, eris.Wrap(err, "validate process specification")
	}
	credential, err := credentialFor(spec)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(spec.Executable)
	cmd.Args = append([]string(nil), spec.Argv...)
	cmd.Dir = spec.WorkingDirectory
	cmd.Env = spec.environment()

	running := &runningProcess{
		cmd:             cmd,
		spec:            spec,
		processWaitDone: make(chan struct{}),
		done:            make(chan struct{}),
	}
	if spec.PTY != nil {
		err = running.startPTY(credential)
	} else {
		err = running.startPipes(credential)
	}
	if err != nil {
		return nil, err
	}
	slog.Default().With("component", "server-process").Debug(
		"started command process",
		"pid", running.cmd.Process.Pid,
		"uid", spec.UID,
		"gid", spec.GID,
		"pty", spec.PTY != nil,
		"executable", spec.Executable,
	)

	go running.wait()
	go func() {
		select {
		case <-ctx.Done():
			running.Terminate(context.Cause(ctx))
		case <-running.done:
		}
	}()
	return running, nil
}

type runningProcess struct {
	cmd  *exec.Cmd
	spec Spec

	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	pty    *os.File

	stdinMu     sync.Mutex
	stdinClosed bool

	processWaitDone chan struct{}
	done            chan struct{}
	waitMu          sync.Mutex
	result          command.ExitResult
	terminating     bool
	completed       bool
	doneOnce        sync.Once

	terminateOnce sync.Once
}

func (p *runningProcess) startPipes(credential *syscall.Credential) error {
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		return eris.Wrap(err, "create process stdin pipe")
	}
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		_ = stdinRead.Close()
		_ = stdinWrite.Close()
		return eris.Wrap(err, "create process stdout pipe")
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		_ = stdinRead.Close()
		_ = stdinWrite.Close()
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
		return eris.Wrap(err, "create process stderr pipe")
	}
	p.cmd.Stdin = stdinRead
	p.cmd.Stdout = stdoutWrite
	p.cmd.Stderr = stderrWrite
	p.cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: credential,
		Setpgid:    true,
	}
	if err := p.cmd.Start(); err != nil {
		_ = stdinRead.Close()
		_ = stdinWrite.Close()
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
		_ = stderrRead.Close()
		_ = stderrWrite.Close()
		return eris.Wrap(err, "start process")
	}
	_ = stdinRead.Close()
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	p.stdin = stdinWrite
	p.stdout = stdoutRead
	p.stderr = stderrRead
	return nil
}

func (p *runningProcess) startPTY(credential *syscall.Credential) error {
	attrs := &syscall.SysProcAttr{
		Credential: credential,
		Setsid:     true,
		Setctty:    true,
	}
	master, err := pty.StartWithAttrs(p.cmd, &pty.Winsize{
		Rows: uint16(p.spec.PTY.Rows),
		Cols: uint16(p.spec.PTY.Columns),
	}, attrs)
	if err != nil {
		return eris.Wrap(err, "start process with PTY")
	}
	p.pty = master
	p.stdin = master
	p.stdout = &eofOnPTYClose{file: master}
	return nil
}

func (p *runningProcess) Stdout() io.Reader {
	if p == nil {
		return nil
	}
	return p.stdout
}

func (p *runningProcess) Stderr() io.Reader {
	if p == nil {
		return nil
	}
	return p.stderr
}

func (p *runningProcess) WriteStdin(ctx context.Context, data []byte) error {
	if p == nil {
		return eris.New("running process is required")
	}
	if err := normalizeContext(ctx).Err(); err != nil {
		return err
	}
	p.stdinMu.Lock()
	if p.stdinClosed {
		p.stdinMu.Unlock()
		return io.ErrClosedPipe
	}
	stdin := p.stdin
	p.stdinMu.Unlock()
	for len(data) > 0 {
		n, err := stdin.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func (p *runningProcess) CloseStdin() error {
	if p == nil {
		return nil
	}
	p.stdinMu.Lock()
	defer p.stdinMu.Unlock()
	if p.stdinClosed {
		return nil
	}
	p.stdinClosed = true
	if p.pty != nil {
		// A PTY is one bidirectional descriptor. Closing it would also discard
		// output and usually send SIGHUP, so command EOF only stops local input.
		return nil
	}
	return p.stdin.Close()
}

func (p *runningProcess) Resize(ctx context.Context, size command.WindowSize) error {
	if p == nil || p.pty == nil {
		return eris.New("process does not have a PTY")
	}
	if err := normalizeContext(ctx).Err(); err != nil {
		return err
	}
	if size.Rows == 0 || size.Rows > 65535 || size.Columns == 0 || size.Columns > 65535 {
		return eris.New("PTY dimensions are invalid")
	}
	if err := pty.Setsize(p.pty, &pty.Winsize{
		Rows: uint16(size.Rows),
		Cols: uint16(size.Columns),
	}); err != nil {
		return eris.Wrap(err, "resize process PTY")
	}
	slog.Default().With("component", "server-process").Debug(
		"resized command PTY",
		"pid", p.cmd.Process.Pid,
		"rows", size.Rows,
		"columns", size.Columns,
	)
	return nil
}

func (p *runningProcess) Wait() command.ExitResult {
	if p == nil {
		return command.ExitResult{RuntimeFailure: "process owner is unavailable"}
	}
	<-p.done
	p.waitMu.Lock()
	defer p.waitMu.Unlock()
	return p.result
}

func (p *runningProcess) Terminate(cause error) {
	if p == nil {
		return
	}
	p.terminateOnce.Do(func() {
		p.waitMu.Lock()
		if p.completed {
			p.waitMu.Unlock()
			return
		}
		p.terminating = true
		p.waitMu.Unlock()
		slog.Default().With("component", "server-process").Debug(
			"terminating command process group",
			"pid", p.cmd.Process.Pid,
			"cause", cause,
		)
		go p.terminate(cause)
	})
}

func (p *runningProcess) CloseOutput() error {
	if p == nil {
		return nil
	}
	if p.stdout != nil {
		_ = p.stdout.Close()
	}
	if p.stderr != nil {
		_ = p.stderr.Close()
	}
	return nil
}

func (p *runningProcess) terminate(_ error) {
	_ = p.CloseStdin()
	if p.cmd.Process == nil {
		p.complete()
		return
	}
	processGroup := -p.cmd.Process.Pid
	_ = syscall.Kill(processGroup, syscall.SIGTERM)

	timer := time.NewTimer(p.spec.grace())
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if errors.Is(syscall.Kill(processGroup, 0), syscall.ESRCH) {
			<-p.processWaitDone
			p.complete()
			return
		}
		select {
		case <-timer.C:
			_ = syscall.Kill(processGroup, syscall.SIGKILL)
			<-p.processWaitDone
			p.complete()
			return
		case <-ticker.C:
		}
	}
}

func (p *runningProcess) wait() {
	err := p.cmd.Wait()
	result := exitResult(err)
	p.waitMu.Lock()
	p.result = result
	p.waitMu.Unlock()
	slog.Default().With("component", "server-process").Debug(
		"command process exited",
		"pid", p.cmd.Process.Pid,
		"status", result.Status,
		"signal", result.Signal,
		"runtime_failure", result.RuntimeFailure,
	)
	close(p.processWaitDone)

	p.waitMu.Lock()
	if p.terminating {
		p.waitMu.Unlock()
		return
	}
	p.terminating = true
	p.waitMu.Unlock()
	p.terminate(nil)
}

func (p *runningProcess) complete() {
	p.waitMu.Lock()
	p.completed = true
	p.waitMu.Unlock()
	p.closeDone()
}

func (p *runningProcess) closeDone() {
	p.doneOnce.Do(func() {
		close(p.done)
	})
}

func exitResult(err error) command.ExitResult {
	if err == nil {
		return command.ExitResult{Status: 0}
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		return command.ExitResult{RuntimeFailure: "process wait failed"}
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok {
		return command.ExitResult{RuntimeFailure: "process status is unavailable"}
	}
	if status.Signaled() {
		name := unix.SignalName(status.Signal())
		if name == "" {
			name = status.Signal().String()
		}
		return command.ExitResult{Signal: name}
	}
	return command.ExitResult{Status: status.ExitStatus()}
}

func credentialFor(spec Spec) (*syscall.Credential, error) {
	if os.Geteuid() == 0 {
		return &syscall.Credential{
			Uid:    spec.UID,
			Gid:    spec.GID,
			Groups: append([]uint32(nil), spec.SupplementaryGroups...),
		}, nil
	}
	if uint32(os.Geteuid()) != spec.UID || uint32(os.Getegid()) != spec.GID {
		return nil, eris.Errorf(
			"unprivileged runner identity mismatch: current %d:%d, requested %d:%d",
			os.Geteuid(),
			os.Getegid(),
			spec.UID,
			spec.GID,
		)
	}
	currentGroups, err := os.Getgroups()
	if err != nil {
		return nil, eris.Wrap(err, "read current supplementary groups")
	}
	normalized := make([]uint32, 0, len(currentGroups))
	for _, group := range currentGroups {
		if uint32(group) != spec.GID {
			normalized = append(normalized, uint32(group))
		}
	}
	slices.Sort(normalized)
	requested := append([]uint32(nil), spec.SupplementaryGroups...)
	slices.Sort(requested)
	if !slices.Equal(normalized, requested) {
		return nil, eris.Errorf(
			"unprivileged runner supplementary groups mismatch: current %v, requested %v",
			normalized,
			requested,
		)
	}
	return &syscall.Credential{
		Uid:         spec.UID,
		Gid:         spec.GID,
		NoSetGroups: true,
	}, nil
}

type eofOnPTYClose struct {
	file *os.File
	once sync.Once
}

func (r *eofOnPTYClose) Read(buffer []byte) (int, error) {
	n, err := r.file.Read(buffer)
	if errors.Is(err, syscall.EIO) {
		err = io.EOF
	}
	if err != nil {
		_ = r.Close()
	}
	return n, err
}

func (r *eofOnPTYClose) Close() error {
	var err error
	r.once.Do(func() {
		err = r.file.Close()
	})
	return err
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

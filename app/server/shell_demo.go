package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"

	serverauthz "github.com/Mikadore/mygosh/app/server/authz"
	usermodel "github.com/Mikadore/mygosh/lib/account"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/service"
	"github.com/Mikadore/mygosh/lib/service/servicepb"
	sessionmux "github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/rotisserie/eris"
)

const remotePath = "/usr/local/bin:/usr/bin:/bin"

type ShellDemo struct {
	session     *sessionmux.Session
	shell       string
	credentials serverauthz.ConnectionCredentials
	authz       *serverauthz.Authz
	logger      *slog.Logger
}

func NewShellDemo(
	sess *sessionmux.Session,
	shell string,
	credentials serverauthz.ConnectionCredentials,
	authorization *serverauthz.Authz,
	logger *slog.Logger,
) *ShellDemo {
	return &ShellDemo{
		session:     sess,
		shell:       shell,
		credentials: credentials,
		authz:       authorization,
		logger:      logging.Resolve(logger),
	}
}

func (d *ShellDemo) Run(ctx context.Context) error {
	ctx = normalizeServerContext(ctx)
	if d == nil || d.session == nil {
		return eris.New("server session is required")
	}
	if d.shell == "" {
		return eris.New("server shell is required")
	}
	if d.authz == nil {
		return eris.New("server authorization is required")
	}
	account := d.credentials.Account()
	if account.Username == "" || account.HomeDir == "" {
		return eris.New("authorized account is incomplete")
	}
	shell := account.LoginShell
	if shell == "" {
		shell = d.shell
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	handler := newShellSessionHandler(runCtx, shell, d.credentials, d.authz, d.logger)
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- d.session.Run(runCtx, handler)
	}()
	if err := d.session.WaitUntilRunning(runCtx); err != nil {
		return eris.Wrap(err, "start server session")
	}

	select {
	case err := <-handler.done:
		cancelRun()
		closeErr := d.session.Close()
		runErr := <-runErrCh
		if errors.Is(runErr, context.Canceled) {
			runErr = nil
		}
		return errors.Join(err, closeErr, runErr)
	case err := <-runErrCh:
		if err == nil {
			return nil
		}
		return eris.Wrap(err, "run server session")
	case <-runCtx.Done():
		_ = d.session.Close()
		return context.Cause(runCtx)
	}
}

type shellSessionHandler struct {
	ctx         context.Context
	shell       string
	credentials serverauthz.ConnectionCredentials
	authz       *serverauthz.Authz
	logger      *slog.Logger

	mu              sync.Mutex
	channelAccepted bool
	channelHandler  *shellChannelHandler
	doneOnce        sync.Once
	done            chan error
}

func newShellSessionHandler(
	ctx context.Context,
	shell string,
	credentials serverauthz.ConnectionCredentials,
	authorization *serverauthz.Authz,
	logger *slog.Logger,
) *shellSessionHandler {
	return &shellSessionHandler{
		ctx:         ctx,
		shell:       shell,
		credentials: credentials,
		authz:       authorization,
		logger:      logging.Resolve(logger),
		done:        make(chan error, 1),
	}
}

func (h *shellSessionHandler) OnChannelOpen(_ context.Context, _ *sessionmux.Channel, req sessionmux.ChannelOpenRequest) sessionmux.ChannelOpenDecision {
	h.mu.Lock()
	defer h.mu.Unlock()

	if req.Type != service.ChannelTypeSession {
		return sessionmux.ChannelOpenDecision{
			Code:    "unsupported-channel-type",
			Message: "only session channels are supported",
		}
	}
	if h.channelAccepted {
		return sessionmux.ChannelOpenDecision{
			Code:    "too-many-channels",
			Message: "only one session channel is supported",
		}
	}

	lease, err := h.authz.OpenSession(h.ctx, h.credentials, serverauthz.SessionRequest{
		ChannelType: req.Type,
		Payload:     req.Payload,
	})
	if err != nil {
		h.logger.Error("session authorization failed", "err", err)
		return sessionmux.ChannelOpenDecision{
			Code:    "session-not-authorized",
			Message: "session is not authorized",
		}
	}

	channelHandler := newShellChannelHandler(
		h.ctx,
		h.shell,
		h.credentials.Account(),
		lease,
		h.logger,
		h.onChannelFinished,
	)
	h.channelAccepted = true
	h.channelHandler = channelHandler
	return sessionmux.ChannelOpenDecision{
		OK:      true,
		Handler: channelHandler,
	}
}

func (h *shellSessionHandler) OnGlobalRequest(_ context.Context, _ sessionmux.GlobalRequest) sessionmux.GlobalResponse {
	return sessionmux.GlobalResponse{
		Code:    "unsupported-global-request",
		Message: "global requests are not supported",
	}
}

func (h *shellSessionHandler) OnDisconnect(_ context.Context, err error) {
	h.mu.Lock()
	channelHandler := h.channelHandler
	h.mu.Unlock()
	if channelHandler != nil {
		channelHandler.stop()
	}
	h.finish(err)
}

func (h *shellSessionHandler) onChannelFinished(err error) {
	h.finish(err)
}

func (h *shellSessionHandler) finish(err error) {
	h.doneOnce.Do(func() {
		h.done <- err
	})
}

type shellChannelState uint8

const (
	shellChannelAwaitingPTY shellChannelState = iota
	shellChannelAwaitingExec
	shellChannelRunning
	shellChannelFinished
)

type shellChannelHandler struct {
	ctx      context.Context
	shell    string
	account  usermodel.Account
	logger   *slog.Logger
	finished func(error)

	mu              sync.Mutex
	state           shellChannelState
	ptyRequest      *servicepb.PtyRequest
	process         *remotePTYProcess
	processFinished bool
	peerClosed      bool
	finishErr       error
	lease           serverauthz.SessionLease
	leaseOnce       sync.Once
	leaseErr        error
}

func newShellChannelHandler(
	ctx context.Context,
	shell string,
	account usermodel.Account,
	lease serverauthz.SessionLease,
	logger *slog.Logger,
	finished func(error),
) *shellChannelHandler {
	return &shellChannelHandler{
		ctx:      ctx,
		shell:    shell,
		account:  account,
		lease:    lease,
		logger:   logging.Resolve(logger),
		finished: finished,
	}
}

func (h *shellChannelHandler) OnRequest(_ context.Context, ch *sessionmux.Channel, req sessionmux.ChannelRequest) sessionmux.ChannelResponse {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch req.Type {
	case service.RequestTypePTY:
		return h.handlePTYRequestLocked(req)
	case service.RequestTypeExec:
		return h.handleExecRequestLocked(ch, req)
	case service.RequestTypeWindowChange:
		return h.handleWindowChangeLocked(req)
	default:
		return sessionmux.ChannelResponse{
			Code:    "unsupported-channel-request",
			Message: "unsupported server channel request",
		}
	}
}

func (h *shellChannelHandler) OnRequestReplied(_ context.Context, _ *sessionmux.Channel, req sessionmux.ChannelRequest, response sessionmux.ChannelResponse, sendErr error) {
	if req.Type != service.RequestTypeExec || !response.OK {
		return
	}

	h.mu.Lock()
	process := h.process
	h.mu.Unlock()
	if process == nil {
		return
	}
	if sendErr != nil {
		process.stop()
		h.markProcessFinished(eris.Wrap(sendErr, "send exec response"))
		return
	}
	process.start()
}

func (h *shellChannelHandler) OnEOF(_ context.Context, _ *sessionmux.Channel) {
	h.stop()
}

func (h *shellChannelHandler) OnClose(_ context.Context, _ *sessionmux.Channel) {
	h.mu.Lock()
	h.peerClosed = true
	process := h.process
	noProcess := process == nil
	shouldFinish, finishErr := h.shouldFinishLocked()
	h.mu.Unlock()

	if process != nil {
		process.stop()
	}
	if noProcess {
		h.finished(h.closeLease())
		return
	}
	if shouldFinish {
		h.finished(errors.Join(finishErr, h.closeLease()))
	}
}

func (h *shellChannelHandler) handlePTYRequestLocked(req sessionmux.ChannelRequest) sessionmux.ChannelResponse {
	if h.state != shellChannelAwaitingPTY {
		return sessionmux.ChannelResponse{
			Code:    "invalid-request-order",
			Message: "PTY has already been requested",
		}
	}

	var ptyRequest servicepb.PtyRequest
	if err := service.UnmarshalPayload(req.Payload, &ptyRequest); err != nil {
		return sessionmux.ChannelResponse{
			Code:    "invalid-pty-request",
			Message: "invalid PTY request",
		}
	}

	h.ptyRequest = &ptyRequest
	h.state = shellChannelAwaitingExec
	return sessionmux.ChannelResponse{OK: true}
}

func (h *shellChannelHandler) handleExecRequestLocked(ch *sessionmux.Channel, req sessionmux.ChannelRequest) sessionmux.ChannelResponse {
	if h.state != shellChannelAwaitingExec {
		return sessionmux.ChannelResponse{
			Code:    "invalid-request-order",
			Message: "exec requires exactly one accepted PTY request",
		}
	}

	var execRequest servicepb.ExecRequest
	if err := service.UnmarshalPayload(req.Payload, &execRequest); err != nil {
		return sessionmux.ChannelResponse{
			Code:    "invalid-exec-request",
			Message: "invalid exec request",
		}
	}

	process, err := startRemotePTYProcess(
		h.ctx,
		ch,
		h.shell,
		execRequest.GetCommand(),
		h.ptyRequest,
		h.account,
		h.logger,
		h.markProcessFinished,
	)
	if err != nil {
		h.logger.Error("failed to start remote command", "err", err)
		return sessionmux.ChannelResponse{
			Code:    "exec-start-failed",
			Message: "failed to start remote command",
		}
	}

	h.process = process
	h.state = shellChannelRunning
	return sessionmux.ChannelResponse{OK: true}
}

func (h *shellChannelHandler) handleWindowChangeLocked(req sessionmux.ChannelRequest) sessionmux.ChannelResponse {
	if h.state != shellChannelRunning || h.process == nil {
		return sessionmux.ChannelResponse{
			Code:    "invalid-request-order",
			Message: "terminal resize requires a running command",
		}
	}

	var size servicepb.TerminalSize
	if err := service.UnmarshalPayload(req.Payload, &size); err != nil {
		return sessionmux.ChannelResponse{
			Code:    "invalid-terminal-size",
			Message: "invalid terminal size",
		}
	}
	if err := h.process.resize(tty.Size{Width: int(size.GetCols()), Height: int(size.GetRows())}); err != nil {
		return sessionmux.ChannelResponse{
			Code:    "terminal-resize-failed",
			Message: "failed to resize terminal",
		}
	}
	return sessionmux.ChannelResponse{OK: true}
}

func (h *shellChannelHandler) stop() {
	h.mu.Lock()
	process := h.process
	h.mu.Unlock()
	if process != nil {
		process.stop()
	}
	_ = h.closeLease()
}

func (h *shellChannelHandler) markProcessFinished(err error) {
	err = errors.Join(err, h.closeLease())
	h.mu.Lock()
	h.processFinished = true
	h.state = shellChannelFinished
	h.finishErr = errors.Join(h.finishErr, err)
	shouldFinish, finishErr := h.shouldFinishLocked()
	h.mu.Unlock()

	if shouldFinish {
		h.finished(finishErr)
	}
}

func (h *shellChannelHandler) closeLease() error {
	h.leaseOnce.Do(func() {
		if h.lease != nil {
			h.leaseErr = h.lease.Close()
		}
	})
	return h.leaseErr
}

func (h *shellChannelHandler) shouldFinishLocked() (bool, error) {
	return h.processFinished && h.peerClosed, h.finishErr
}

type remotePTYProcess struct {
	ctx      context.Context
	cancel   context.CancelFunc
	channel  *sessionmux.Channel
	command  *exec.Cmd
	vtty     *tty.VTTY
	logger   *slog.Logger
	finished func(error)

	startOnce sync.Once
	stopOnce  sync.Once
}

func startRemotePTYProcess(
	ctx context.Context,
	channel *sessionmux.Channel,
	shell string,
	command string,
	ptyRequest *servicepb.PtyRequest,
	account usermodel.Account,
	logger *slog.Logger,
	finished func(error),
) (*remotePTYProcess, error) {
	processCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(processCtx, shell, "-c", command)
	cmd.Dir = account.HomeDir
	cmd.Env = []string{
		"HOME=" + account.HomeDir,
		"USER=" + account.Username,
		"LOGNAME=" + account.Username,
		"SHELL=" + shell,
		"TERM=" + ptyRequest.GetTerm(),
		"PATH=" + remotePath,
	}
	if credential := commandCredential(account); credential != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	}

	vtty, err := tty.CreateVTTY(tty.Size{
		Width:  int(ptyRequest.GetCols()),
		Height: int(ptyRequest.GetRows()),
	}, cmd)
	if err != nil {
		cancel()
		return nil, eris.Wrap(err, "create remote PTY")
	}

	return &remotePTYProcess{
		ctx:      processCtx,
		cancel:   cancel,
		channel:  channel,
		command:  cmd,
		vtty:     vtty,
		logger:   logging.Resolve(logger),
		finished: finished,
	}, nil
}

func commandCredential(account usermodel.Account) *syscall.Credential {
	if uint32(os.Geteuid()) == account.Id && uint32(os.Getegid()) == account.PrimaryGroup.Id {
		return nil
	}

	groups := make([]uint32, 0, len(account.SupplementaryGroups))
	for _, group := range account.SupplementaryGroups {
		groups = append(groups, group.Id)
	}
	return &syscall.Credential{
		Uid:    account.Id,
		Gid:    account.PrimaryGroup.Id,
		Groups: groups,
	}
}

func (p *remotePTYProcess) start() {
	p.startOnce.Do(func() {
		go p.forwardInput()
		go p.forwardOutputAndWait()
	})
}

func (p *remotePTYProcess) stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		_ = p.vtty.Close()
	})
}

func (p *remotePTYProcess) resize(size tty.Size) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	return p.vtty.Resize(size)
}

func (p *remotePTYProcess) forwardInput() {
	for {
		frame, err := p.channel.Recv(p.ctx)
		if err != nil {
			p.stop()
			return
		}
		if err := writeServerFull(p.vtty, frame); err != nil {
			p.logger.Error("failed to write remote PTY input", "err", err)
			p.stop()
			return
		}
	}
}

func (p *remotePTYProcess) forwardOutputAndWait() {
	var outputErr error
	buffer := make([]byte, 4096)
	for {
		n, err := p.vtty.Read(buffer)
		if n > 0 {
			if sendErr := p.channel.Send(p.ctx, buffer[:n]); sendErr != nil {
				outputErr = eris.Wrap(sendErr, "send remote PTY output")
				p.stop()
				break
			}
		}
		if err != nil {
			if !terminalClosed(err) {
				outputErr = eris.Wrap(err, "read remote PTY output")
			}
			break
		}
	}

	exitCode, waitErr := waitExit(p.command)
	statusPayload, statusErr := service.MarshalPayload(&servicepb.ExitStatus{Code: int32(exitCode)})
	if statusErr == nil {
		_, statusErr = p.channel.SendRequest(context.WithoutCancel(p.ctx), service.RequestTypeExitStatus, statusPayload, false)
	}
	eofErr := p.channel.CloseWrite()
	closeErr := p.channel.Close()
	p.cancel()
	_ = p.vtty.Close()

	p.finished(errors.Join(outputErr, waitErr, statusErr, eofErr, closeErr))
}

func terminalClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EIO)
}

func waitExit(command *exec.Cmd) (int, error) {
	err := command.Wait()
	if err == nil {
		return 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 1, err
}

func writeServerFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func normalizeServerContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

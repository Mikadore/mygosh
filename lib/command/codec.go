package command

import (
	"sort"
	"strings"

	"buf.build/go/protovalidate"
	"github.com/Mikadore/mygosh/lib/command/commandpb"
	"github.com/rotisserie/eris"
	"google.golang.org/protobuf/proto"
)

func marshalMessage(message proto.Message, maximum int) ([]byte, error) {
	if message == nil {
		return nil, eris.New("command message is required")
	}
	if err := protovalidate.Validate(message); err != nil {
		return nil, eris.Wrap(err, "validate command message")
	}
	frame, err := proto.Marshal(message)
	if err != nil {
		return nil, eris.Wrap(err, "encode command message")
	}
	if len(frame) == 0 {
		return nil, eris.New("encoded command frame is empty")
	}
	if maximum > 0 && len(frame) > maximum {
		return nil, eris.Errorf("command frame exceeds maximum size: %d > %d", len(frame), maximum)
	}
	return frame, nil
}

func unmarshalMessage(frame []byte, message proto.Message) error {
	if len(frame) == 0 {
		return eris.New("empty command frame")
	}
	if message == nil {
		return eris.New("command message is required")
	}
	proto.Reset(message)
	if err := proto.Unmarshal(frame, message); err != nil {
		return eris.Wrap(err, "decode command message")
	}
	if err := protovalidate.Validate(message); err != nil {
		return eris.Wrap(err, "validate command message")
	}
	return nil
}

func encodeStart(request StartRequest) (*commandpb.ClientFrame, error) {
	start := &commandpb.Start{ProtocolVersion: ProtocolVersion}
	switch request.Kind {
	case StartShell:
		if strings.TrimSpace(request.Command) != "" {
			return nil, eris.New("shell start must not include a command")
		}
		start.Target = &commandpb.Start_Shell{Shell: &commandpb.Shell{}}
	case StartExec:
		if strings.TrimSpace(request.Command) == "" {
			return nil, eris.New("exec command is required")
		}
		start.Target = &commandpb.Start_Exec{Exec: &commandpb.Exec{Command: request.Command}}
	default:
		return nil, eris.Errorf("unsupported command start kind %d", request.Kind)
	}
	if request.PTY != nil {
		start.Pty = &commandpb.Pty{
			Terminal: request.PTY.Terminal,
			Rows:     request.PTY.Rows,
			Columns:  request.PTY.Columns,
		}
	}
	names := make([]string, 0, len(request.Environment))
	for name := range request.Environment {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		start.Environment = append(start.Environment, &commandpb.Environment{
			Name:  name,
			Value: request.Environment[name],
		})
	}
	return &commandpb.ClientFrame{
		Kind: &commandpb.ClientFrame_Start{Start: start},
	}, nil
}

// EncodeClientStart validates and encodes one command start frame.
func EncodeClientStart(request StartRequest, maximum int) ([]byte, error) {
	message, err := encodeStart(request)
	if err != nil {
		return nil, err
	}
	return marshalMessage(message, maximum)
}

// EncodeClientStdin validates and chunks command input into client frames.
func EncodeClientStdin(data []byte, maximum int) ([][]byte, error) {
	return chunkedFrames(data, maximum, func(chunk []byte) *commandpb.ClientFrame {
		return &commandpb.ClientFrame{
			Kind: &commandpb.ClientFrame_Stdin{
				Stdin: &commandpb.Stdin{Data: append([]byte(nil), chunk...)},
			},
		}
	})
}

// EncodeClientStdinEOF encodes the one-shot client stdin EOF frame.
func EncodeClientStdinEOF(maximum int) ([]byte, error) {
	return marshalMessage(&commandpb.ClientFrame{
		Kind: &commandpb.ClientFrame_StdinEof{StdinEof: &commandpb.StdinEof{}},
	}, maximum)
}

// EncodeClientWindowChange encodes a PTY window-size update.
func EncodeClientWindowChange(size WindowSize, maximum int) ([]byte, error) {
	return marshalMessage(&commandpb.ClientFrame{
		Kind: &commandpb.ClientFrame_WindowChange{
			WindowChange: &commandpb.WindowChange{Rows: size.Rows, Columns: size.Columns},
		},
	}, maximum)
}

type ServerEventKind uint8

const (
	ServerEventStartResult ServerEventKind = iota + 1
	ServerEventStdout
	ServerEventStderr
	ServerEventExit
)

// ServerEvent is the protobuf-independent result of decoding one server frame.
type ServerEvent struct {
	Kind     ServerEventKind
	Accepted bool
	Code     string
	Message  string
	Data     []byte
	Exit     ExitResult
}

// DecodeServerEvent validates and decodes one server-to-client command frame.
func DecodeServerEvent(frame []byte) (ServerEvent, error) {
	var message commandpb.ServerFrame
	if err := unmarshalMessage(frame, &message); err != nil {
		return ServerEvent{}, err
	}

	switch kind := message.GetKind().(type) {
	case *commandpb.ServerFrame_StartResult:
		result := kind.StartResult
		if result.GetAccepted() && (result.GetCode() != "" || result.GetMessage() != "") {
			return ServerEvent{}, protocolErrorf("accepted start result contains rejection details")
		}
		return ServerEvent{
			Kind:     ServerEventStartResult,
			Accepted: result.GetAccepted(),
			Code:     result.GetCode(),
			Message:  result.GetMessage(),
		}, nil
	case *commandpb.ServerFrame_Stdout:
		return ServerEvent{
			Kind: ServerEventStdout,
			Data: append([]byte(nil), kind.Stdout.GetData()...),
		}, nil
	case *commandpb.ServerFrame_Stderr:
		return ServerEvent{
			Kind: ServerEventStderr,
			Data: append([]byte(nil), kind.Stderr.GetData()...),
		}, nil
	case *commandpb.ServerFrame_Exit:
		event := ServerEvent{Kind: ServerEventExit}
		switch result := kind.Exit.GetResult().(type) {
		case *commandpb.Exit_Status:
			event.Exit.Status = int(result.Status)
		case *commandpb.Exit_Signal:
			event.Exit.Signal = result.Signal
		case *commandpb.Exit_RuntimeFailure:
			event.Exit.RuntimeFailure = result.RuntimeFailure.GetMessage()
		default:
			return ServerEvent{}, protocolErrorf("exit result is required")
		}
		return event, nil
	default:
		return ServerEvent{}, protocolErrorf("unsupported server frame %T", message.GetKind())
	}
}

func decodeStart(start *commandpb.Start) (StartRequest, error) {
	if start == nil {
		return StartRequest{}, eris.New("start frame is required")
	}
	request := StartRequest{}
	switch target := start.GetTarget().(type) {
	case *commandpb.Start_Shell:
		request.Kind = StartShell
	case *commandpb.Start_Exec:
		request.Kind = StartExec
		request.Command = target.Exec.GetCommand()
	default:
		return StartRequest{}, eris.New("start target is required")
	}
	if pty := start.GetPty(); pty != nil {
		request.PTY = &PTYRequest{
			Terminal: pty.GetTerminal(),
			Rows:     pty.GetRows(),
			Columns:  pty.GetColumns(),
		}
	}
	request.Environment = make(map[string]string, len(start.GetEnvironment()))
	for _, entry := range start.GetEnvironment() {
		if entry == nil {
			return StartRequest{}, eris.New("nil environment entry")
		}
		if strings.ContainsAny(entry.GetName(), "=\x00") {
			return StartRequest{}, eris.Errorf("invalid environment variable %q", entry.GetName())
		}
		if strings.ContainsRune(entry.GetValue(), '\x00') {
			return StartRequest{}, eris.Errorf("environment variable %q contains NUL", entry.GetName())
		}
		if _, exists := request.Environment[entry.GetName()]; exists {
			return StartRequest{}, eris.Errorf("duplicate environment variable %q", entry.GetName())
		}
		request.Environment[entry.GetName()] = entry.GetValue()
	}
	return request, nil
}

func chunkedFrames[T proto.Message](
	data []byte,
	maximum int,
	build func([]byte) T,
) ([][]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if maximum <= 0 {
		maximum = defaultMaximumFrameSize
	}
	frames := make([][]byte, 0, (len(data)/maximum)+1)
	for len(data) > 0 {
		low, high := 1, min(len(data), maximum)
		best := 0
		var encoded []byte
		for low <= high {
			mid := low + (high-low)/2
			frame, err := marshalMessage(build(data[:mid]), maximum)
			if err == nil {
				best = mid
				encoded = frame
				low = mid + 1
				continue
			}
			high = mid - 1
		}
		if best == 0 {
			return nil, eris.Errorf("maximum command frame size %d cannot carry data", maximum)
		}
		frames = append(frames, encoded)
		data = data[best:]
	}
	return frames, nil
}

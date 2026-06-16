package client

import (
	"fmt"
	"net"
	"strings"

	"github.com/rotisserie/eris"
)

type connectTarget struct {
	username string
	host     string
	port     string
}

func parseConnectTarget(raw string) (connectTarget, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return connectTarget{}, eris.New("connect target is required")
	}

	out := connectTarget{}
	if idx := strings.LastIndex(target, "@"); idx >= 0 {
		out.username = target[:idx]
		target = target[idx+1:]
		if out.username == "" {
			return connectTarget{}, eris.New("connect target username is required")
		}
		if target == "" {
			return connectTarget{}, eris.New("connect target host is required")
		}
	}

	host, port, err := splitConnectHostPort(target)
	if err != nil {
		return connectTarget{}, err
	}
	out.host = host
	out.port = port
	return out, nil
}

func splitConnectHostPort(target string) (string, string, error) {
	if strings.HasPrefix(target, "[") {
		end := strings.Index(target, "]")
		if end < 0 {
			return "", "", eris.New("connect target has an unterminated bracketed host")
		}

		host := target[1:end]
		if host == "" {
			return "", "", eris.New("connect target host is required")
		}

		rest := target[end+1:]
		switch {
		case rest == "":
			return host, "", nil
		case strings.HasPrefix(rest, ":"):
			port := rest[1:]
			if port == "" {
				return "", "", eris.New("connect target port is required")
			}
			return host, port, nil
		default:
			return "", "", eris.New("connect target has unexpected characters after bracketed host")
		}
	}

	host, port, err := net.SplitHostPort(target)
	if err == nil {
		if host == "" {
			return "", "", eris.New("connect target host is required")
		}
		if port == "" {
			return "", "", eris.New("connect target port is required")
		}
		return host, port, nil
	}

	if strings.Count(target, ":") == 1 {
		host, port, _ := strings.Cut(target, ":")
		if host == "" {
			return "", "", eris.New("connect target host is required")
		}
		if port == "" {
			return "", "", eris.New("connect target port is required")
		}
		return host, port, nil
	}

	return target, "", nil
}

func (t connectTarget) dialAddress(defaultPort int) string {
	port := t.port
	if port == "" {
		port = fmt.Sprintf("%d", defaultPort)
	}
	return net.JoinHostPort(t.host, port)
}

func (t connectTarget) referenceIdentity() string {
	return t.host
}

func (t connectTarget) resolvedUsername() string {
	if t.username != "" {
		return t.username
	}
	return localUsername()
}

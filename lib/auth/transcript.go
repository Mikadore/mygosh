package auth

import (
	"crypto/sha256"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/rotisserie/eris"
	"google.golang.org/protobuf/proto"
)

func HashHostAuthInit(msg *authpb.HostAuthInit) ([]byte, error) {
	if msg == nil {
		return nil, eris.New("host auth init is required")
	}
	return hashProtoMessage(msg)
}

func HashServerAuthMessage(msg *authpb.ServerAuth) ([]byte, error) {
	if msg == nil {
		return nil, eris.New("server auth is required")
	}
	return HashServerAuthFields(msg.GetServerHostKey(), msg.GetServerNonce())
}

func HashServerAuthFields(serverHostKey []byte, serverNonce []byte) ([]byte, error) {
	return hashProtoMessage(&authpb.ServerAuth{
		ServerHostKey: cloneBytes(serverHostKey),
		ServerNonce:   cloneBytes(serverNonce),
	})
}

func hashProtoMessage(msg proto.Message) ([]byte, error) {
	packet, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, eris.Wrap(err, "marshal auth transcript")
	}

	sum := sha256.Sum256(packet)
	return sum[:], nil
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

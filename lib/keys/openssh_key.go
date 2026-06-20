package keys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/rotisserie/eris"
)

const (
	opensshKeyV1Magic            = "openssh-key-v1\x00"
	opensshEd25519KeyType        = "ssh-ed25519"
	opensshEd25519PrivateKeySize = ed25519.PrivateKeySize
)

func ParseOpensshPrivateKeyRaw(raw []byte) (Keypair, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return Keypair{}, eris.New("decode OpenSSH private key: empty input")
	}

	if bytes.HasPrefix(raw, []byte(opensshKeyV1Magic)) {
		return parseOpensshPrivateKeyV1(raw)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return Keypair{}, eris.New("decode OpenSSH private key: expected PEM block or openssh-key-v1 payload")
	}
	if block.Type != "OPENSSH PRIVATE KEY" {
		return Keypair{}, eris.Errorf("decode OpenSSH private key: unexpected PEM type %q", block.Type)
	}

	return parseOpensshPrivateKeyV1(block.Bytes)
}

func parseOpensshPrivateKeyV1(key []byte) (Keypair, error) {
	cursor := bincoder.NewCursor(key).WithMaxBytes(16 * 1024)
	cursor.ExpectBytes([]byte(opensshKeyV1Magic))
	ciphername := cursor.UTF8String()
	kdfname := cursor.UTF8String()
	kdfoptions := cursor.Bytes()
	numKeys := cursor.U32()

	if err := cursor.Err(); err != nil {
		return Keypair{}, eris.Wrap(err, "decode private key header")
	}

	if ciphername != "none" || kdfname != "none" {
		return Keypair{}, eris.Errorf("encrypted keys not supported: cipher=%q kdf=%q", ciphername, kdfname)
	}
	if len(kdfoptions) != 0 {
		return Keypair{}, eris.Errorf("unexpected kdf options for unencrypted key")
	}
	if numKeys != 1 {
		return Keypair{}, eris.Errorf("only one key per file is supported")
	}

	publicBlob := cursor.Bytes()
	privateBlob := cursor.Bytes()
	if err := cursor.Done(); err != nil {
		return Keypair{}, eris.Wrap(err, "decode private key envelope")
	}

	public, err := parseOpensshEd25519PublicBlob(publicBlob)
	if err != nil {
		return Keypair{}, err
	}

	privateKey, err := parseOpensshEd25519PrivateBlob(privateBlob)
	if err != nil {
		return Keypair{}, err
	}

	if !bytes.Equal(public, privateKey.Public) {
		return Keypair{}, eris.Errorf("public key mismatch between public and private sections")
	}

	return privateKey, nil
}

func parseOpensshEd25519PublicBlob(blob []byte) ([]byte, error) {
	cursor := bincoder.NewCursor(blob).WithMaxBytes(1024)
	keyType := cursor.UTF8String()
	public := cursor.Bytes()
	if err := cursor.Done(); err != nil {
		return nil, eris.Wrap(err, "decode public key blob")
	}
	if keyType != opensshEd25519KeyType {
		return nil, eris.Errorf("unsupported public key type %q", keyType)
	}
	if len(public) != ed25519PublicKeySize {
		return nil, eris.Errorf("public key length %d does not match expected length %d", len(public), ed25519PublicKeySize)
	}
	return cloneBytes(public), nil
}

func parseOpensshEd25519PrivateBlob(blob []byte) (Keypair, error) {
	cursor := bincoder.NewCursor(blob).WithMaxBytes(16 * 1024)

	check1 := cursor.U32()
	check2 := cursor.U32()
	if err := cursor.Err(); err != nil {
		return Keypair{}, eris.Wrap(err, "decode private key block")
	}
	if check1 != check2 {
		return Keypair{}, eris.Errorf("checkints don't match %d != %d", check1, check2)
	}

	keyType := cursor.UTF8String()
	public := cursor.Bytes()
	private := cursor.Bytes()
	comment := cursor.UTF8String()
	if err := cursor.Err(); err != nil {
		return Keypair{}, eris.Wrap(err, "decode ed25519 private key")
	}

	if keyType != opensshEd25519KeyType {
		return Keypair{}, eris.Errorf("unsupported private key type %q", keyType)
	}
	if len(public) != ed25519PublicKeySize {
		return Keypair{}, eris.Errorf("public key length %d does not match expected length %d", len(public), ed25519PublicKeySize)
	}
	if len(private) != opensshEd25519PrivateKeySize {
		return Keypair{}, eris.Errorf("private key length %d does not match expected length %d", len(private), opensshEd25519PrivateKeySize)
	}
	if !bytes.Equal(private[ed25519SeedSize:], public) {
		return Keypair{}, eris.Errorf("embedded public key does not match public key field")
	}

	padding := cursor.Rest()
	if !validOpensshPadding(padding) {
		return Keypair{}, eris.Errorf("invalid OpenSSH private key padding")
	}

	keypair := Keypair{
		Public:  cloneBytes(public),
		Private: cloneBytes(private[:ed25519SeedSize]),
		Comment: comment,
	}
	if err := keypair.Validate(); err != nil {
		return Keypair{}, eris.Wrap(err, "decode ed25519 private key")
	}

	return keypair, nil
}

func validOpensshPadding(padding []byte) bool {
	for i, b := range padding {
		if b != byte(i+1) {
			return false
		}
	}
	return true
}

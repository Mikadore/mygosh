package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/rotisserie/eris"
)

const (
	opensshKeyV1Magic     = "openssh-key-v1\x00"
	opensshEd25519KeyType = "ssh-ed25519"
	ed25519PublicKeySize  = 32
	ed25519PrivateKeySize = 64
)

type opensshEd25519PrivateKey struct {
	Public  []byte
	Private []byte
	Seed    []byte
	Comment string
}

func ParseOpensshEd25519PrivateKeyV1(key []byte) (opensshEd25519PrivateKey, error) {
	cursor := bincoder.NewCursor(key).WithMaxBytes(16 * 1024)
	cursor.ExpectBytes([]byte(opensshKeyV1Magic))
	ciphername := cursor.UTF8String()
	kdfname := cursor.UTF8String()
	kdfoptions := cursor.Bytes()
	numKeys := cursor.U32()

	if err := cursor.Err(); err != nil {
		return opensshEd25519PrivateKey{}, eris.Wrap(err, "decode private key header")
	}

	if ciphername != "none" || kdfname != "none" {
		return opensshEd25519PrivateKey{}, eris.Errorf("encrypted keys not supported: cipher=%q kdf=%q", ciphername, kdfname)
	}
	if len(kdfoptions) != 0 {
		return opensshEd25519PrivateKey{}, eris.Errorf("unexpected kdf options for unencrypted key")
	}
	if numKeys != 1 {
		return opensshEd25519PrivateKey{}, eris.Errorf("only one key per file is supported")
	}

	publicBlob := cursor.Bytes()
	privateBlob := cursor.Bytes()
	if err := cursor.Done(); err != nil {
		return opensshEd25519PrivateKey{}, eris.Wrap(err, "decode private key envelope")
	}

	public, err := parseOpensshEd25519PublicBlob(publicBlob)
	if err != nil {
		return opensshEd25519PrivateKey{}, err
	}

	privateKey, err := parseOpensshEd25519PrivateBlob(privateBlob)
	if err != nil {
		return opensshEd25519PrivateKey{}, err
	}

	if !bytes.Equal(public, privateKey.Public) {
		return opensshEd25519PrivateKey{}, eris.Errorf("public key mismatch between public and private sections")
	}

	return privateKey, nil
}

func PrintOpensshKeyV1(w io.Writer, key []byte) error {
	privateKey, err := ParseOpensshEd25519PrivateKeyV1(key)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "Key type: %s\n", opensshEd25519KeyType)
	fmt.Fprintf(w, "Public hex: %s\n", hex.EncodeToString(privateKey.Public))
	fmt.Fprintf(w, "Public base64: %s\n", base64.StdEncoding.EncodeToString(privateKey.Public))
	fmt.Fprintf(w, "Private hex: %s\n", hex.EncodeToString(privateKey.Private))
	fmt.Fprintf(w, "Private base64: %s\n", base64.StdEncoding.EncodeToString(privateKey.Private))
	fmt.Fprintf(w, "Seed hex: %s\n", hex.EncodeToString(privateKey.Seed))
	fmt.Fprintf(w, "Seed base64: %s\n", base64.StdEncoding.EncodeToString(privateKey.Seed))
	fmt.Fprintf(w, "Comment: %s\n", privateKey.Comment)
	return nil
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
	return public, nil
}

func parseOpensshEd25519PrivateBlob(blob []byte) (opensshEd25519PrivateKey, error) {
	cursor := bincoder.NewCursor(blob).WithMaxBytes(16 * 1024)

	check1 := cursor.U32()
	check2 := cursor.U32()
	if err := cursor.Err(); err != nil {
		return opensshEd25519PrivateKey{}, eris.Wrap(err, "decode private key block")
	}
	if check1 != check2 {
		return opensshEd25519PrivateKey{}, eris.Errorf("checkints don't match %d != %d", check1, check2)
	}

	keyType := cursor.UTF8String()
	public := cursor.Bytes()
	private := cursor.Bytes()
	comment := cursor.UTF8String()
	if err := cursor.Err(); err != nil {
		return opensshEd25519PrivateKey{}, eris.Wrap(err, "decode ed25519 private key")
	}

	if keyType != opensshEd25519KeyType {
		return opensshEd25519PrivateKey{}, eris.Errorf("unsupported private key type %q", keyType)
	}
	if len(public) != ed25519PublicKeySize {
		return opensshEd25519PrivateKey{}, eris.Errorf("public key length %d does not match expected length %d", len(public), ed25519PublicKeySize)
	}
	if len(private) != ed25519PrivateKeySize {
		return opensshEd25519PrivateKey{}, eris.Errorf("private key length %d does not match expected length %d", len(private), ed25519PrivateKeySize)
	}
	if !bytes.Equal(private[ed25519PublicKeySize:], public) {
		return opensshEd25519PrivateKey{}, eris.Errorf("embedded public key does not match public key field")
	}

	padding := cursor.Rest()
	if !validOpensshPadding(padding) {
		return opensshEd25519PrivateKey{}, eris.Errorf("invalid OpenSSH private key padding")
	}

	return opensshEd25519PrivateKey{
		Public:  append([]byte(nil), public...),
		Private: append([]byte(nil), private...),
		Seed:    append([]byte(nil), private[:ed25519PublicKeySize]...),
		Comment: comment,
	}, nil
}

func validOpensshPadding(padding []byte) bool {
	for i, b := range padding {
		if b != byte(i+1) {
			return false
		}
	}
	return true
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %v [filename]\n", os.Args[0])
		os.Exit(1)
	}
	content, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error reading %v: %v\n", os.Args[1], err)
		os.Exit(1)
	}
	blob, _ := pem.Decode(content)
	if blob == nil || blob.Type != "OPENSSH PRIVATE KEY" {
		fmt.Printf("File isn't an openssh private key")
		os.Exit(1)
	}
	err = PrintOpensshKeyV1(os.Stdout, blob.Bytes)
	if err != nil {
		fmt.Printf("Error decoding key: %v\n", err)
		os.Exit(1)
	}

}

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/rotisserie/eris"
)

func PrintOpensshKeyV1(key []byte) error {
	cursor := bincoder.NewCursor(key)
	cursor.ExpectBytes([]byte("openssh-key-v1\000"))
	ciphername := cursor.UTF8String()
	kdfname := cursor.UTF8String()
	// kdfoptions
	_ = cursor.Bytes()
	num_keys := cursor.U32()

	if cursor.Err() != nil {
		return eris.Wrapf(cursor.Err(), "Invalid private key header") 
	}

	if num_keys != 1 {
		return eris.Errorf("Only one key per file is supported")
	}

	if ciphername != "none" || kdfname != "none" {
		return eris.Errorf("Encrypted keys not supported")
	}
	
	pubType := cursor.UTF8String()
	if cursor.Err() != nil || pubType != "ssh-ed25519" {
		return eris.Errorf("Invalid key type %v", pubType)
	}
	pub := cursor.Bytes()
	privateBlob := cursor.Bytes()
	if cursor.Err() != nil {
		return cursor.Err()
	}
	cursor = bincoder.NewCursor(privateBlob)
	ck1 := cursor.U32()
	ck2 := cursor.U32()
	if ck1 != ck2 {
		return eris.Errorf("checkints don't match %v != %v", ck1, ck2)
	}
	priv := cursor.Bytes()
	comment := cursor.UTF8String()
	if cursor.Err() != nil {
		return cursor.Err()
	}
	fmt.Printf("Public:\n")
	fmt.Printf("%v ", strings.ToValidUTF8(string(pub), "."))
	fmt.Printf("%v ", hex.EncodeToString(pub))
	fmt.Printf("%v", base64.StdEncoding.EncodeToString(pub))
	fmt.Println()
	fmt.Printf("Private:\n")
	fmt.Printf("%v ", strings.ToValidUTF8(string(priv), "."))
	fmt.Printf("%v ", hex.EncodeToString(priv))
	fmt.Printf("%v", base64.StdEncoding.EncodeToString(priv))
	fmt.Println()
	fmt.Printf("Comment: %v\n", comment)
	return nil
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
	if blob.Type != "OPENSSH PRIVATE KEY" {
		fmt.Printf("File isn't an openssh private key")
		os.Exit(1)
	}
	err = PrintOpensshKeyV1(blob.Bytes)
	if err != nil {
		fmt.Printf("Error decoding key: %v\n", err)
		os.Exit(1)
	}

}
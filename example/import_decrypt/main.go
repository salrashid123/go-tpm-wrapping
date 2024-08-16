package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
)

const ()

var (
	tpmPath               = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	userAuth              = flag.String("userAuth", "", "object Password")
	encrypting_public_key = flag.String("encrypting_public_key", "", "Public Key to encrypt with")
	encryptedBlob         = flag.String("encryptedBlob", "encrypted.json", "Encrypted Blob")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	b, err := os.ReadFile(*encrypting_public_key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading public encrypting key %v\n", err)
		os.Exit(1)
	}

	wrapper := tpmwrap.NewRemoteWrapper()
	_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		tpmwrap.TPM_PATH:              *tpmPath,
		tpmwrap.ENCRYPTING_PUBLIC_KEY: hex.EncodeToString(b),
		tpmwrap.USER_AUTH:             *userAuth,
	}))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
		os.Exit(1)
	}

	eb, err := os.ReadFile(*encryptedBlob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading encrypted blob %v\n", err)
		os.Exit(1)
	}
	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(eb, newBlobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error unmarshalling %v\n", err)
		os.Exit(1)
	}

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Decrypted %s\n", string(plaintext))

}

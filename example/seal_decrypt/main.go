package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
)

const ()

var (
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	userAuth      = flag.String("userAuth", "", "object Password")
	pcrValues     = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 16:abc,23:foo")
	encryptedBlob = flag.String("encryptedBlob", "encrypted.json", "Encrypted Blob")
)

const (
	TPMSeal = iota
	TPMImport
)

func main() {
	flag.Parse()

	ctx := context.Background()

	wrapper := tpmwrap.NewWrapper()
	_, err := wrapper.SetConfig(ctx,
		tpmwrap.WithTPMPath(*tpmPath),
		tpmwrap.WithPCRValues(*pcrValues),
		tpmwrap.WithUserAuth(*userAuth))

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
		os.Exit(1)
	}

	b, err := os.ReadFile(*encryptedBlob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading encrypted file %v\n", err)
		os.Exit(1)
	}

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)
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

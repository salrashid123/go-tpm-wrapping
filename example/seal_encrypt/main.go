package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
)

const ()

var (
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pcrValues     = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 16:abc,23:foo")
	userAuth      = flag.String("userAuth", "", "object Password")
	dataToEncrypt = flag.String("dataToEncrypt", "foo", "data to encrypt")
	encryptedBlob = flag.String("encryptedBlob", "encrypted.json", "Encrypted Blob")
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

	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Encrypted: %s\n", hex.EncodeToString(blobInfo.Ciphertext))

	b, err := protojson.Marshal(blobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling bytes %v\n", err)
		os.Exit(1)
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, b, "", "\t")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling json %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Marshalled encryptedBlob: %s\n", prettyJSON.String())

	err = os.WriteFile(*encryptedBlob, b, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing encrypted blob %v\n", err)
		os.Exit(1)
	}

}

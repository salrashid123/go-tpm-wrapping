package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
)

const ()

var (
	dataToEncrypt         = flag.String("dataToEncrypt", "foo", "data to encrypt")
	pcrValues             = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 16:abc,23:foo")
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

	_, err = wrapper.SetConfig(ctx,
		tpmwrap.WithEncryptingPublicKey(hex.EncodeToString(b)),
		tpmwrap.WithPCRValues(*pcrValues),
		tpmwrap.WithUserAuth(*userAuth))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
		os.Exit(1)
	}

	aad := []byte("myaad")

	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt), wrapping.WithAad(aad))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting %v\n", err)
		os.Exit(1)
	}

	eb, err := protojson.Marshal(blobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling bytes %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Encrypted: %s\n", hex.EncodeToString(blobInfo.Ciphertext))

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, eb, "", "\t")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling json %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Marshalled encryptedBlob: %s\n", prettyJSON.String())

	err = os.WriteFile(*encryptedBlob, eb, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file %v\n", err)
		os.Exit(1)
	}

}

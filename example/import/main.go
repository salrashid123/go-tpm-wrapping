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
	tpmPath               = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pcrValues             = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 16:abc,23:foo")
	encrypting_public_key = flag.String("encrypting_public_key", "", "Public Key to encrypt with")
	encrypted_blob        = flag.String("encrypted_blob", "/tmp/encrypted.dat", "File to write the encrypted data to")
	mode                  = flag.String("mode", "encrypt", "mode: encrypt or decrypt")
)

func main() {
	flag.Parse()

	ctx := context.Background()
	if *mode == "encrypt" {
		b, err := os.ReadFile(*encrypting_public_key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading public encrypting key %v\n", err)
			os.Exit(1)
		}

		wrapper := tpmwrap.NewRemoteWrapper()
		_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"encrypting_public_key": hex.EncodeToString(b),
			"pcr_values":            *pcrValues,
		}))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
			os.Exit(1)
		}
		blobInfo, err := wrapper.Encrypt(ctx, []byte("foo"))
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
		error := json.Indent(&prettyJSON, eb, "", "\t")
		if error != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling json %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Marshalled encryptedBlob: %s\n", string(prettyJSON.Bytes()))

		err = os.WriteFile(*encrypted_blob, eb, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file %v\n", err)
			os.Exit(1)
		}
	}

	if *mode == "decrypt" {

		wrapper := tpmwrap.NewRemoteWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"tpm_path": *tpmPath,
		}))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
			os.Exit(1)
		}

		eb, err := os.ReadFile(*encrypted_blob)
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
}

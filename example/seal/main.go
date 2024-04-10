package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
)

const ()

var (
	tpmPath   = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pcrs      = flag.String("pcrs", "", "PCR Bound value (increasing order, comma separated)")
	extendPCR = flag.String("extendPCR", "", "Extend a PCR and attempt to decrypt")
)

func main() {
	flag.Parse()

	ctx := context.Background()
	wrapper := tpmwrap.NewWrapper()
	_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		"tpm_path": *tpmPath,
		"pcrs":     *pcrs,
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

	fmt.Printf("Encrypted: %s\n", hex.EncodeToString(blobInfo.Ciphertext))

	b, err := protojson.Marshal(blobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling bytes %v\n", err)
		os.Exit(1)
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, b, "", "\t")
	if error != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling json %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Marshalled encryptedBlob: %s\n", string(prettyJSON.Bytes()))

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

	if *extendPCR != "" {
		fmt.Println("======= Extend PCR  ========")
		rwc, err := tpm2.OpenTPM(*tpmPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't open TPM %q: %v", *tpmPath, err)
			os.Exit(1)
		}
		defer rwc.Close()
		j, err := strconv.Atoi(*extendPCR)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error  converting pcr string %v", err)
			os.Exit(1)
		}

		pcrval, err := tpm2.ReadPCR(rwc, j, tpm2.AlgSHA256)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to ReadPCR: %v", err)
			os.Exit(1)
		}
		fmt.Printf("   Current PCR(%s) %s", *extendPCR, hex.EncodeToString(pcrval))

		pcrToExtend := tpmutil.Handle(j)

		err = tpm2.PCRExtend(rwc, pcrToExtend, tpm2.AlgSHA256, pcrval, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to Extend PCR: %v", err)
			os.Exit(1)
		}

		pcrval, err = tpm2.ReadPCR(rwc, j, tpm2.AlgSHA256)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to ReadPCR: %v", err)
			os.Exit(1)
		}
		fmt.Printf("   New PCR(%d) %s", j, hex.EncodeToString(pcrval))

		err = rwc.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error closing tpm %v\n", err)
			os.Exit(1)
		}
		plaintext, err = wrapper.Decrypt(ctx, blobInfo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Decrypted %s\n", string(plaintext))

	}
}

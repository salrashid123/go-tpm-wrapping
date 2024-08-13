package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	mode = flag.String("mode", "seal", "operation mode: seal or import")

	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	//parentPass    = flag.String("parentPass", "", "TPM Parent Key password")
	keyPass = flag.String("keyPass", "", "TPM Key password")

	pcrValues     = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 16:abc,23:foo")
	dataToEncrypt = flag.String("dataToEncrypt", "foo", "data to encrypt")

	decrypt = flag.Bool("decrypt", false, "set --decrypt perform decryption (default encrypt)")
	debug   = flag.Bool("debug", false, "verbose output")

	encrypting_public_key = flag.String("encrypting_public_key", "", "Public Key to encrypt with")

	encryptedBlob = flag.String("encryptedBlob", "/tmp/encrypted.json", "Encrypted Blob")

	sessionEncryptionName = flag.String("tpm-session-encrypt-with-name", "", "hex encoded TPM object 'name' to use with an encrypted session")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()

	ctx := context.Background()
	if *mode == "seal" {
		if !*decrypt {
			wrapper := tpmwrap.NewWrapper()
			_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
				tpmwrap.TPM_PATH:   *tpmPath,
				tpmwrap.USER_AUTH:  *keyPass,
				tpmwrap.PCR_VALUES: *pcrValues,
			}))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
				os.Exit(1)
			}
			wrapper.SetConfig(ctx, tpmwrap.WithDebug(*debug))
			blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error encrypting %v\n", err)
				os.Exit(1)
			}

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

			err = os.WriteFile(*encryptedBlob, b, 0666)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error writing encrypted blob %v\n", err)
				os.Exit(1)
			}
			if *debug {
				fmt.Printf("Encrypted Blob: %s\n", prettyJSON.String())
				fmt.Printf("wrote encrypted blob: %s\n", *encryptedBlob)
			}

		} else {

			wrapper := tpmwrap.NewWrapper()
			_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
				tpmwrap.TPM_PATH:   *tpmPath,
				tpmwrap.PCR_VALUES: *pcrValues,
				tpmwrap.USER_AUTH:  *keyPass,
			}))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
				os.Exit(1)
			}
			wrapper.SetConfig(ctx, tpmwrap.WithDebug(*debug))
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
			if *debug {
				fmt.Println("Decrypted:")
			}
			fmt.Printf("%s", string(plaintext))
		}

	} else if *mode == "import" {
		if !*decrypt {
			b, err := os.ReadFile(*encrypting_public_key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading public encrypting key %v\n", err)
				os.Exit(1)
			}

			wrapper := tpmwrap.NewRemoteWrapper()
			_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
				tpmwrap.TPM_PATH:              *tpmPath,
				tpmwrap.ENCRYPTING_PUBLIC_KEY: hex.EncodeToString(b),
				tpmwrap.USER_AUTH:             *keyPass,
				tpmwrap.PCR_VALUES:            *pcrValues,
			}))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
				os.Exit(1)
			}
			wrapper.SetConfig(ctx, tpmwrap.WithDebug(*debug))
			blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error encrypting %v\n", err)
				os.Exit(1)
			}

			eb, err := protojson.Marshal(blobInfo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshalling bytes %v\n", err)
				os.Exit(1)
			}
			if *debug {
				fmt.Printf("Encrypted: %s\n", hex.EncodeToString(blobInfo.Ciphertext))
			}

			var prettyJSON bytes.Buffer
			err = json.Indent(&prettyJSON, eb, "", "\t")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshalling json %v\n", err)
				os.Exit(1)
			}

			//fmt.Printf("Marshalled encryptedBlob: %s\n", prettyJSON.String())

			err = os.WriteFile(*encryptedBlob, eb, 0666)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error writing encrypted blob %v\n", err)
				os.Exit(1)
			}
			if *debug {
				fmt.Printf("Encrypted Blob: %s\n", prettyJSON.String())
				fmt.Printf("wrote encrypted blob: %s\n", *encryptedBlob)
			}
		} else {

			wrapper := tpmwrap.NewRemoteWrapper()
			_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
				tpmwrap.TPM_PATH:   *tpmPath,
				tpmwrap.USER_AUTH:  *keyPass,
				tpmwrap.PCR_VALUES: *pcrValues,
			}))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
				os.Exit(1)
			}
			wrapper.SetConfig(ctx, tpmwrap.WithDebug(*debug))
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
			if *debug {
				fmt.Println("Decrypted:")
			}
			fmt.Printf("%s", string(plaintext))

		}

	} else {
		fmt.Println("--mode must be either seal or import")
		os.Exit(1)
	}

}

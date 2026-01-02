package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const ()

var (
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	pcrValues     = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 16:abc,23:foo")
	userAuth      = flag.String("userAuth", "", "object Password")
	dataToEncrypt = flag.String("dataToEncrypt", "foo", "data to encrypt")
	encryptedBlob = flag.String("encryptedBlob", "encrypted.json", "Encrypted Blob")
	clientData    = flag.String("clientData", "{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}", "JSON to include as clientdata")
)

const ()

func main() {
	flag.Parse()

	ctx := context.Background()

	wrapper := tpmwrap.NewWrapper()

	_, err := wrapper.SetConfig(ctx,
		tpmwrap.WithTPMPath(*tpmPath),
		tpmwrap.WithPCRValues(*pcrValues),
		tpmwrap.WithUserAuth(*userAuth), tpmwrap.WithClientData(*clientData))
	if err != nil {
		log.Fatalf("Error creating wrapper %v\n", err)
	}

	var dataMap map[string]interface{}
	err = json.Unmarshal([]byte(*clientData), &dataMap)
	if err != nil {
		log.Fatal(err)
	}
	protoStruct, err := structpb.NewStruct(dataMap)
	if err != nil {
		log.Fatal(err)
	}

	jsonBytes, err := json.Marshal(protoStruct.AsMap())
	if err != nil {
		log.Fatalf("failed to marshal to JSON: %v", err)
	}
	hasher := sha256.New()
	hasher.Write(jsonBytes)
	hashBytes := hasher.Sum(nil)

	fmt.Printf("Canonical Hash: %s\n", hex.EncodeToString(hashBytes))

	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt), wrapping.WithAad(hashBytes))
	if err != nil {
		log.Fatalf("Error encrypting %v\n", err)
	}

	fmt.Printf("Encrypted: %s\n", hex.EncodeToString(blobInfo.Ciphertext))

	b, err := protojson.Marshal(blobInfo)
	if err != nil {
		log.Fatalf("Error marshalling bytes %v\n", err)
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, b, "", "\t")
	if err != nil {
		log.Fatalf("Error marshalling json %v\n", err)

	}

	fmt.Printf("Marshalled encryptedBlob: %s\n", prettyJSON.String())

	err = os.WriteFile(*encryptedBlob, b, 0666)
	if err != nil {
		log.Fatalf("Error writing encrypted blob %v\n", err)

	}

}

package main

import (
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
	userAuth      = flag.String("userAuth", "", "object Password")
	pcrValues     = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 16:abc,23:foo")
	encryptedBlob = flag.String("encryptedBlob", "encrypted.json", "Encrypted Blob")

	expectedClientData = flag.String("clientData", "{\"provider\": \"pqc\", \"location\": { \"zone\": \"central\",\"region\": \"us\"}}", "JSON to include as clientdata")
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
		log.Fatalf("Error creating wrapper %v\n", err)
	}

	b, err := os.ReadFile(*encryptedBlob)
	if err != nil {
		log.Fatalf("Error reading encrypted file %v\n", err)
	}

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)
	if err != nil {
		log.Fatalf("Error unmarshalling %v\n", err)
	}

	jsonBytes, err := json.Marshal(newBlobInfo.ClientData.AsMap())
	if err != nil {
		log.Fatalf("failed to marshal to JSON: %v", err)
	}
	hasher := sha256.New()
	hasher.Write(jsonBytes)
	hashBytes := hasher.Sum(nil)

	fmt.Printf("Canonical Hash of client_data from encryptedBlob  %s\n", hex.EncodeToString(hashBytes))

	// expected clientHash

	var dataMap map[string]interface{}
	err = json.Unmarshal([]byte(*expectedClientData), &dataMap)
	if err != nil {
		log.Fatal(err)
	}
	protoStruct, err := structpb.NewStruct(dataMap)
	if err != nil {
		log.Fatal(err)
	}

	ejsonBytes, err := json.Marshal(protoStruct.AsMap())
	if err != nil {
		log.Fatalf("failed to marshal to JSON: %v", err)
	}
	ehasher := sha256.New()
	ehasher.Write(ejsonBytes)
	ehashBytes := ehasher.Sum(nil)

	fmt.Printf("Expected Canonical Hash of client_data as parameter: %s\n", hex.EncodeToString(ehashBytes))

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo, tpmwrap.WithClientData(*expectedClientData), wrapping.WithAad(ehashBytes))
	if err != nil {
		log.Fatalf("Error decrypting %v\n", err)
	}
	fmt.Printf("Decrypted %s\n", string(plaintext))

}

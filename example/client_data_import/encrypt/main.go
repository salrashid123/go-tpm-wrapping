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
	dataToEncrypt         = flag.String("dataToEncrypt", "foo", "data to encrypt")
	pcrValues             = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 16:abc,23:foo")
	userAuth              = flag.String("userAuth", "", "object Password")
	encrypting_public_key = flag.String("encrypting_public_key", "", "Public Key to encrypt with")
	encryptedBlob         = flag.String("encryptedBlob", "encrypted.json", "Encrypted Blob")
	clientData            = flag.String("clientData", "{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}", "JSON to include as clientdata")
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
		tpmwrap.WithUserAuth(*userAuth), tpmwrap.WithClientData(*clientData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
		os.Exit(1)
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

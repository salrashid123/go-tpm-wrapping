package tpmwrap

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strconv"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestImport(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	ek, err := client.EndorsementKeyRSA(tpmDevice)
	require.NoError(t, err)
	defer ek.Close()

	ekRSA, ok := ek.PublicKey().(*rsa.PublicKey)
	require.True(t, ok)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(ekRSA),
		},
	)

	ctx := context.Background()

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)))
	require.NoError(t, err)

	dataToSeal := []byte("foo")

	blobInfo, err := wrapper.Encrypt(ctx, dataToSeal)
	require.NoError(t, err)

	b, err := protojson.Marshal(blobInfo)
	require.NoError(t, err)

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, b, "", "\t")
	require.NoError(t, err)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)
	require.NoError(t, err)

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo)
	require.NoError(t, err)

	require.Equal(t, dataToSeal, plaintext)
}

func TestImportPCR(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	ek, err := client.EndorsementKeyRSA(tpmDevice)
	require.NoError(t, err)
	defer ek.Close()

	ekRSA, ok := ek.PublicKey().(*rsa.PublicKey)
	require.True(t, ok)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(ekRSA),
		},
	)

	ctx := context.Background()
	pcr := 23

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)), WithPCRS(strconv.Itoa(pcr)))
	require.NoError(t, err)

	dataToSeal := []byte("foo")

	blobInfo, err := wrapper.Encrypt(ctx, dataToSeal)
	require.NoError(t, err)

	b, err := protojson.Marshal(blobInfo)
	require.NoError(t, err)

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, b, "", "\t")
	require.NoError(t, err)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)
	require.NoError(t, err)

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo)
	require.NoError(t, err)

	require.Equal(t, dataToSeal, plaintext)
}

func TestImportPCRFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	ek, err := client.EndorsementKeyRSA(tpmDevice)
	require.NoError(t, err)
	defer ek.Close()

	ekRSA, ok := ek.PublicKey().(*rsa.PublicKey)
	require.True(t, ok)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(ekRSA),
		},
	)

	ctx := context.Background()
	pcr := 23
	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)), WithPCRS(strconv.Itoa(pcr)))
	require.NoError(t, err)

	dataToSeal := []byte("foo")

	blobInfo, err := wrapper.Encrypt(ctx, dataToSeal)
	require.NoError(t, err)

	b, err := protojson.Marshal(blobInfo)
	require.NoError(t, err)

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, b, "", "\t")
	require.NoError(t, err)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)
	require.NoError(t, err)

	pcrval, err := tpm2.ReadPCR(tpmDevice, pcr, tpm2.AlgSHA256)
	require.NoError(t, err)

	pcrToExtend := tpmutil.Handle(pcr)

	err = tpm2.PCRExtend(tpmDevice, pcrToExtend, tpm2.AlgSHA256, pcrval, "")
	require.NoError(t, err)

	_, err = wrapper.Decrypt(ctx, newBlobInfo)
	require.Error(t, err)
}

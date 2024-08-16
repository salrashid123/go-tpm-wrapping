package tpmwrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

	rb, err := x509.MarshalPKIXPublicKey(ek.PublicKey())
	require.NoError(t, err)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)
	ek.Close()

	ctx := context.Background()

	wrapper := NewRemoteWrapper()
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

	rb, err := x509.MarshalPKIXPublicKey(ek.PublicKey())
	require.NoError(t, err)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)
	ek.Close()

	ctx := context.Background()

	wrapper := NewRemoteWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)), WithPCRValues("23:0000000000000000000000000000000000000000000000000000000000000000"))
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

	rb, err := x509.MarshalPKIXPublicKey(ek.PublicKey())
	require.NoError(t, err)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)
	ek.Close()

	ctx := context.Background()
	pcr := 23
	wrapper := NewRemoteWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)), WithPCRValues("23:0000000000000000000000000000000000000000000000000000000000000000"))
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

func TestImportEKFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	ek, err := client.EndorsementKeyRSA(tpmDevice)
	require.NoError(t, err)

	rb, err := x509.MarshalPKIXPublicKey(ek.PublicKey())
	require.NoError(t, err)
	ekpemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)
	ek.Close()

	badEK, err := client.NewKey(tpmDevice, tpm2.HandleNull, client.SRKTemplateRSA())
	require.NoError(t, err)

	rbb, err := x509.MarshalPKIXPublicKey(badEK.PublicKey())
	require.NoError(t, err)
	badekpemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rbb,
		},
	)
	badEK.Close()

	ctx := context.Background()

	wrapper := NewRemoteWrapper()

	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(ekpemdata)))
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

	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(badekpemdata)))
	require.NoError(t, err)

	_, err = wrapper.Decrypt(ctx, newBlobInfo)
	require.Error(t, err)
}

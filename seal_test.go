package tpmwrap

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestSeal(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	ctx := context.Background()

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice))
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

func TestSealPCR(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	ctx := context.Background()

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithPCRValues("23:0000000000000000000000000000000000000000000000000000000000000000"))
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

func TestSealPCRFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	ctx := context.Background()

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithPCRValues("23:0000000000000000000000000000000000000000000000000000000000000000"))
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

	pcr := 23

	pcrval, err := tpm2.ReadPCR(tpmDevice, pcr, tpm2.AlgSHA256)
	require.NoError(t, err)

	pcrToExtend := tpmutil.Handle(pcr)

	err = tpm2.PCRExtend(tpmDevice, pcrToExtend, tpm2.AlgSHA256, pcrval, "")
	require.NoError(t, err)

	_, err = wrapper.Decrypt(ctx, newBlobInfo)
	require.Error(t, err)
}

func TestSealPassword(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	ctx := context.Background()

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithUserAuth("foo"))
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

func TestSealPasswordFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	ctx := context.Background()

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithUserAuth("foo"))
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

	wrapper.userAuth = "bar"

	_, err = wrapper.Decrypt(ctx, newBlobInfo)
	require.Error(t, err)
}

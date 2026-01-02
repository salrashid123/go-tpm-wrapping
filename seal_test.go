package tpmwrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"testing"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	swTPMPathB = "127.0.0.1:2341"
)

func TestSeal(t *testing.T) {
	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPathB)
	require.NoError(t, err)
	defer tpmDevice.Close()

	ctx := context.Background()

	keyName := "bar"

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithKeyName(keyName))
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

	require.Equal(t, keyName, newBlobInfo.KeyInfo.KeyId)

	require.Equal(t, dataToSeal, plaintext)
}

func TestSealPCR(t *testing.T) {
	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPathB)
	require.NoError(t, err)
	defer tpmDevice.Close()

	ctx := context.Background()

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithPCRValues("15:0000000000000000000000000000000000000000000000000000000000000000"))
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
	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPathB)
	require.NoError(t, err)
	defer tpmDevice.Close()

	ctx := context.Background()

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithPCRValues("15:0000000000000000000000000000000000000000000000000000000000000000"))
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

	rwr := transport.FromReadWriter(tpmDevice)

	pcr := uint(15)

	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(uint32(pcr)),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  pcrReadRsp.PCRValues.Digests[0].Buffer,
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = wrapper.Decrypt(ctx, newBlobInfo)
	require.Error(t, err)
}

func TestSealPassword(t *testing.T) {
	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPathB)
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

// skip until dictionarylockout is supported
// func TestSealPasswordFail(t *testing.T) {
// 	//tpmDevice, err := simulator.Get()
// 	tpmDevice, err := net.Dial("tcp", swTPMPathB)
// 	require.NoError(t, err)
// 	defer tpmDevice.Close()

// 	ctx := context.Background()

// 	wrapper := NewWrapper()
// 	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithUserAuth("foo"))
// 	require.NoError(t, err)

// 	dataToSeal := []byte("foo")

// 	blobInfo, err := wrapper.Encrypt(ctx, dataToSeal)
// 	require.NoError(t, err)

// 	b, err := protojson.Marshal(blobInfo)
// 	require.NoError(t, err)

// 	var prettyJSON bytes.Buffer
// 	err = json.Indent(&prettyJSON, b, "", "\t")
// 	require.NoError(t, err)

// 	newBlobInfo := &wrapping.BlobInfo{}
// 	err = protojson.Unmarshal(b, newBlobInfo)
// 	require.NoError(t, err)

// 	wrapper.userAuth = "bar"

// 	_, err = wrapper.Decrypt(ctx, newBlobInfo)
// 	require.Error(t, err)
// }

func TestSealEncryptedSessionPassword(t *testing.T) {
	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPathB)
	require.NoError(t, err)
	defer tpmDevice.Close()

	ctx := context.Background()

	rwr := transport.FromReadWriter(tpmDevice)

	createEKRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	outPub, err := createEKRsp.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	akBytes, err := x509.MarshalPKIXPublicKey(rsaPub)
	require.NoError(t, err)

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	flushContextCmd := tpm2.FlushContext{
		FlushHandle: createEKRsp.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	keyName := hex.EncodeToString(createEKRsp.Name.Buffer)
	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithUserAuth("foo"), WithEncryptingPublicKey(hex.EncodeToString(akPubPEM)), WithKeyName(keyName))
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

func TestSealAAD(t *testing.T) {

	ctx := context.Background()

	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPathB)
	require.NoError(t, err)
	defer tpmDevice.Close()

	// for dictionary lockout
	//  https://github.com/google/go-tpm/issues/422
	// rwr := transport.FromReadWriter(tpmDevice)
	// _, err = tpm2.DictionaryAttackLockReset{
	// 	LockHandle: tpm2.TPMRHLockout,
	// }.Execute(rwr)
	// require.NoError(t, err)

	keyName := "bar"

	tests := []struct {
		name          string
		aadEncrypt    []byte
		aadDecrypt    []byte
		shouldSucceed bool
	}{
		{"aadSucceed", []byte("myaad"), []byte("myaad"), true},
		{"aadFail", []byte("myaad"), []byte("bar"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			wrapper := NewWrapper()
			_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithKeyName(keyName))
			require.NoError(t, err)

			dataToSeal := []byte("foo")

			blobInfo, err := wrapper.Encrypt(ctx, dataToSeal, wrapping.WithAad(tc.aadEncrypt))
			require.NoError(t, err)

			b, err := protojson.Marshal(blobInfo)
			require.NoError(t, err)

			var prettyJSON bytes.Buffer
			err = json.Indent(&prettyJSON, b, "", "\t")
			require.NoError(t, err)

			newBlobInfo := &wrapping.BlobInfo{}
			err = protojson.Unmarshal(b, newBlobInfo)
			require.NoError(t, err)

			wrapperD := NewWrapper()
			_, err = wrapperD.SetConfig(ctx, WithTPM(tpmDevice))
			require.NoError(t, err)

			_, err = wrapperD.Decrypt(ctx, newBlobInfo, wrapping.WithAad(tc.aadDecrypt))
			if tc.shouldSucceed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}

		})
	}

}

func TestSealClientDataGlobal(t *testing.T) {

	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPathB)
	require.NoError(t, err)
	defer tpmDevice.Close()

	keyName := "bar"
	ctx := context.Background()

	tests := []struct {
		name              string
		clientDataEncrypt string
		clientDataDecrypt string

		shouldSucceed bool
	}{
		{"ClientDataGlobalSucceed", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider1\"}", true},
		{"ClientDataGlobalFail", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider2\"}", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			wrapper := NewWrapper()
			_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithKeyName(keyName), WithClientData(tc.clientDataEncrypt))
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

			wrapperD := NewWrapper()
			_, err = wrapperD.SetConfig(ctx, WithTPM(tpmDevice), WithClientData(tc.clientDataDecrypt))
			require.NoError(t, err)

			_, err = wrapperD.Decrypt(ctx, newBlobInfo)
			if tc.shouldSucceed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}

}

func TestSealClientDataLocal(t *testing.T) {

	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPathB)
	require.NoError(t, err)
	defer tpmDevice.Close()

	keyName := "bar"
	ctx := context.Background()

	tests := []struct {
		name              string
		clientDataEncrypt string
		clientDataDecrypt string

		shouldSucceed bool
	}{
		{"ClientDataGlobalSucceed", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider1\"}", true},
		{"ClientDataGlobalFail", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider2\"}", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			wrapper := NewWrapper()
			_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithKeyName(keyName))
			require.NoError(t, err)

			dataToSeal := []byte("foo")

			blobInfo, err := wrapper.Encrypt(ctx, dataToSeal, WithClientData(tc.clientDataEncrypt))
			require.NoError(t, err)

			b, err := protojson.Marshal(blobInfo)
			require.NoError(t, err)

			var prettyJSON bytes.Buffer
			err = json.Indent(&prettyJSON, b, "", "\t")
			require.NoError(t, err)

			newBlobInfo := &wrapping.BlobInfo{}
			err = protojson.Unmarshal(b, newBlobInfo)
			require.NoError(t, err)

			wrapperD := NewWrapper()
			_, err = wrapperD.SetConfig(ctx, WithTPM(tpmDevice))
			require.NoError(t, err)

			_, err = wrapperD.Decrypt(ctx, newBlobInfo, WithClientData(tc.clientDataDecrypt))
			if tc.shouldSucceed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestSealClientDataMix(t *testing.T) {

	//tpmDevice, err := simulator.Get()
	tpmDevice, err := net.Dial("tcp", swTPMPathB)
	require.NoError(t, err)
	defer tpmDevice.Close()

	keyName := "bar"
	ctx := context.Background()

	tests := []struct {
		name              string
		clientDataEncrypt string
		clientDataDecrypt string

		shouldSucceed bool
	}{
		{"ClientDataGlobalSucceed", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider1\"}", true},
		{"ClientDataGlobalFail", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider2\"}", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			wrapper := NewWrapper()
			_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithKeyName(keyName), WithClientData(tc.clientDataEncrypt))
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

			wrapperD := NewWrapper()
			_, err = wrapperD.SetConfig(ctx, WithTPM(tpmDevice))
			require.NoError(t, err)

			_, err = wrapperD.Decrypt(ctx, newBlobInfo, WithClientData(tc.clientDataDecrypt))
			if tc.shouldSucceed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

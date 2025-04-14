package tpmwrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	badekpem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxy8vxeaGBgMdhcIQxnG+
LHizNlexDpVkh3Sbe86c8FzxaxJi7Gj7MuQrc7YXRfZlROfSVg41Nbd/5EeQQdnP
I7jW1/2+QF1NUOim3Y1exOY+oQvGwiTPfyG47O1DFUmiJYiQ93DOq261y+cCRJ6c
sbLWjIDzJRPuNZ4mSzaeeXHjexHy5Gkp1OTPcKbvRGb9q+Z4xf1PVlBV3x22ykKx
UdLg8tf2ZvOtc6H8i3D26Nmx8nSROk9HtegMLcrG7RHrmhoqGH/3ug8/S3SlyI2k
YgQz8rsK1ZoGdOmeOIm7FHUwA1TZfXDMIAzIygAD2PDUHVKAlhumT2lB9hWkkwDT
wwIDAQAB
-----END PUBLIC KEY-----`
)

func TestImportRSA(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	cCreateEEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: cCreateEEK.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	rb, err := x509.MarshalPKIXPublicKey(rsaPub)
	require.NoError(t, err)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: cCreateEEK.ObjectHandle,
	}
	_, err = flushContextCmd.Execute(rwr)
	require.NoError(t, err)

	ctx := context.Background()

	keyName := "bar"

	wrapper := NewRemoteWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)), WithKeyName(keyName))
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

func TestImportECC(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	cCreateEEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: cCreateEEK.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	ecDetail, err := outPub.Parameters.ECCDetail()
	require.NoError(t, err)

	crv, err := ecDetail.CurveID.Curve()
	require.NoError(t, err)

	eccUnique, err := outPub.Unique.ECC()
	require.NoError(t, err)

	pubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: cCreateEEK.ObjectHandle,
	}
	_, err = flushContextCmd.Execute(rwr)
	require.NoError(t, err)

	rb, err := x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)

	ctx := context.Background()

	keyName := "bar"

	wrapper := NewRemoteWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)), WithKeyName(keyName))
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

func TestImportPCR(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	cCreateEEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: cCreateEEK.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	rb, err := x509.MarshalPKIXPublicKey(rsaPub)
	require.NoError(t, err)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: cCreateEEK.ObjectHandle,
	}
	_, err = flushContextCmd.Execute(rwr)
	require.NoError(t, err)

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

	rwr := transport.FromReadWriter(tpmDevice)

	cCreateEEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: cCreateEEK.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	rb, err := x509.MarshalPKIXPublicKey(rsaPub)
	require.NoError(t, err)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: cCreateEEK.ObjectHandle,
	}
	_, err = flushContextCmd.Execute(rwr)
	require.NoError(t, err)

	ctx := context.Background()
	pcr := uint(23)
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

func TestImportEKFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	cCreateEEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: cCreateEEK.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	rb, err := x509.MarshalPKIXPublicKey(rsaPub)
	require.NoError(t, err)
	ekpemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)
	flushContextCmd := tpm2.FlushContext{
		FlushHandle: cCreateEEK.ObjectHandle,
	}
	_, err = flushContextCmd.Execute(rwr)
	require.NoError(t, err)

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

	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString([]byte(badekpem))))
	require.NoError(t, err)

	_, err = wrapper.Decrypt(ctx, newBlobInfo)
	require.Error(t, err)
}

func TestImportPassword(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	cCreateEEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: cCreateEEK.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	rb, err := x509.MarshalPKIXPublicKey(rsaPub)
	require.NoError(t, err)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)
	flushContextCmd := tpm2.FlushContext{
		FlushHandle: cCreateEEK.ObjectHandle,
	}
	_, err = flushContextCmd.Execute(rwr)
	require.NoError(t, err)

	ctx := context.Background()

	pass := "foo"

	wrapper := NewRemoteWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)), WithUserAuth(pass))
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

	newwrapper := NewRemoteWrapper()
	_, err = newwrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)), WithUserAuth(pass))
	require.NoError(t, err)

	plaintext, err := newwrapper.Decrypt(ctx, newBlobInfo)
	require.NoError(t, err)

	require.Equal(t, dataToSeal, plaintext)
}

func TestImportPasswordFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	cCreateEEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: cCreateEEK.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	rb, err := x509.MarshalPKIXPublicKey(rsaPub)
	require.NoError(t, err)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rb,
		},
	)

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: cCreateEEK.ObjectHandle,
	}
	_, err = flushContextCmd.Execute(rwr)
	require.NoError(t, err)

	ctx := context.Background()

	pass := "foo"
	badpass := "bar"

	wrapper := NewRemoteWrapper()
	_, err = wrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)), WithUserAuth(pass))
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

	newwrapper := NewRemoteWrapper()
	_, err = newwrapper.SetConfig(ctx, WithTPM(tpmDevice), WithEncryptingPublicKey(hex.EncodeToString(pemdata)), WithUserAuth(badpass))
	require.NoError(t, err)

	_, err = newwrapper.Decrypt(ctx, newBlobInfo)
	require.Error(t, err)
}

package tpmwrap

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/tpm"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	context "golang.org/x/net/context"
	"google.golang.org/protobuf/proto"
)

const (
	WrapperTypeRemoteTPM wrapping.WrapperType = "tpmimport"
)

// Configures and manages the TPM SRK encryption wrapper
//
//	Values here are set using setConfig or options
type RemoteWrapper struct {
	tpmPath             string
	tpmDevice           io.ReadWriteCloser
	pcrs                string
	userAgent           string
	currentKeyId        *atomic.Value
	pcrValues           string
	encryptingPublicKey string
}

var (
	_ wrapping.Wrapper = (*RemoteWrapper)(nil)
)

// Initialize a TPM based encryption wrapper
func NewRemoteWrapper() *RemoteWrapper {
	s := &RemoteWrapper{
		currentKeyId: new(atomic.Value),
	}
	s.currentKeyId.Store("")
	return s
}

// Set the configuration options
func (s *RemoteWrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	s.userAgent = opts.withUserAgent
	switch {
	case os.Getenv(EnvTPMPath) != "" && !opts.Options.WithDisallowEnvVars:
		s.tpmPath = os.Getenv(EnvTPMPath)
	case opts.withTPMPath != "":
		s.tpmPath = opts.withTPMPath
	}

	switch {
	case os.Getenv(EnvPCRS) != "" && !opts.Options.WithDisallowEnvVars:
		s.pcrs = os.Getenv(EnvPCRS)
	case opts.withPCRS != "":
		s.pcrs = opts.withPCRS
	}

	switch {
	case os.Getenv(EnvEncryptingPublicKey) != "" && !opts.Options.WithDisallowEnvVars:
		s.encryptingPublicKey = os.Getenv(EnvEncryptingPublicKey)
	case opts.withEncryptingPublicKey != "":
		s.encryptingPublicKey = opts.withEncryptingPublicKey
	}

	switch {
	case os.Getenv(EnvPCRValues) != "" && !opts.Options.WithDisallowEnvVars:
		s.pcrValues = os.Getenv(EnvPCRValues)
	case opts.withPCRValues != "":
		s.pcrValues = opts.withPCRValues
	}

	if opts.withTPM != nil {
		if s.tpmPath != "" {
			return nil, fmt.Errorf("cannot specify both TPMPath and TPMDevice")
		}
		s.tpmDevice = opts.withTPM
	}

	// Map that holds non-sensitive configuration info to return
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata[TPM_PATH] = s.tpmPath
	wrapConfig.Metadata[PCR_VALUES] = s.pcrValues
	wrapConfig.Metadata[ENCRYPTING_PUBLIC_KEY] = s.encryptingPublicKey
	return wrapConfig, nil
}

func (s *RemoteWrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return WrapperTypeRemoteTPM, nil
}

func (s *RemoteWrapper) KeyId(_ context.Context) (string, error) {
	return s.currentKeyId.Load().(string), nil
}

// Encrypts data using a TPM's Storage Root Key (SRK)
func (s *RemoteWrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	if s.encryptingPublicKey == "" {
		return nil, fmt.Errorf("encrypting public key must be set")
	}

	pcrMap, _, err := getPCRMap(tpm.HashAlgo_SHA256, s.pcrValues)
	if err != nil {
		return nil, fmt.Errorf(" Could not get PCRMap: %s", err)
	}
	pcrs := &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: pcrMap}

	pubPEMData, err := hex.DecodeString(s.encryptingPublicKey)
	if err != nil {
		return nil, fmt.Errorf(" error decoding public key  : %v", err)
	}

	block, _ := pem.Decode(pubPEMData)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(" unable parsing encrypting public key : %v", err)
	}

	blob, err := server.CreateImportBlob(publicKey, env.Key, pcrs)
	if err != nil {
		return nil, fmt.Errorf(" unable to CreateImportBlob : %v", err)
	}
	sealed, err := proto.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("marshaling error: %v", err)
	}

	// as convention, we'll save the public key's fingerpint/hash as the keyID
	hasher := sha256.New()
	hasher.Write([]byte(s.encryptingPublicKey))
	keyName := hex.EncodeToString((hasher.Sum(nil)))

	// Store current key id value
	s.currentKeyId.Store(keyName)

	if len(env.Iv) == 0 {
		env.Iv = make([]byte, aes.BlockSize)
		// or to use the random source from the tpm itself: https://github.com/salrashid123/tpmrand
		if _, err := io.ReadFull(rand.Reader, env.Iv); err != nil {
			return nil, errors.New("error creating initialization vector")
		}
	}

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  TPMImport,
			KeyId:      keyName,
			WrappedKey: sealed,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext.
func (s *RemoteWrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in.Ciphertext == nil {
		return nil, fmt.Errorf("given ciphertext for decryption is nil")
	}

	var rwc io.ReadWriteCloser
	if s.tpmDevice != nil {
		rwc = s.tpmDevice
	} else {
		var err error
		rwc, err = tpm2.OpenTPM(s.tpmPath)
		if err != nil {
			return nil, fmt.Errorf("can't open TPM %q: %v", s.tpmPath, err)
		}
		defer rwc.Close()
	}

	// Default to mechanism used before key info was stored
	if in.KeyInfo == nil {
		in.KeyInfo = &wrapping.KeyInfo{
			Mechanism: TPMImport,
		}
	}

	var pcrList = []int{}
	if s.pcrs != "" {
		strpcrs := strings.Split(s.pcrs, ",")
		for _, i := range strpcrs {
			j, err := strconv.Atoi(i)
			if err != nil {
				return nil, fmt.Errorf("error  converting pcr string %v", err)
			}
			pcrList = append(pcrList, j)
		}
	}

	var plaintext []byte
	switch in.KeyInfo.Mechanism {
	case TPMImport:
		ek, err := client.EndorsementKeyRSA(rwc)
		if err != nil {
			return nil, fmt.Errorf("unable to load EK from TPM: %v", err)
		}

		blob := &tpmpb.ImportBlob{}
		err = proto.Unmarshal(in.KeyInfo.WrappedKey, blob)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling error: %v", err)
		}
		decrypted, err := ek.Import(blob)
		if err != nil {
			return nil, fmt.Errorf("error decrypted key error: %v", err)
		}
		envInfo := &wrapping.EnvelopeInfo{
			Key:        decrypted,
			Iv:         in.Iv,
			Ciphertext: in.Ciphertext,
		}
		plaintext, err = wrapping.EnvelopeDecrypt(envInfo, opt...)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data with envelope: %w", err)
		}

	default:
		return nil, fmt.Errorf("invalid mechanism: %d", in.KeyInfo.Mechanism)
	}

	return plaintext, nil
}

func getPCRMap(algo tpm.HashAlgo, expectedPCRMap string) (map[uint32][]byte, []byte, error) {

	pcrMap := make(map[uint32][]byte)

	if expectedPCRMap == "" {
		return pcrMap, nil, nil
	}
	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm.HashAlgo_SHA1 {
		hsh = sha1.New()
	}
	if algo == tpm.HashAlgo_SHA256 {
		hsh = sha256.New()
	}
	if algo == tpm.HashAlgo_SHA1 || algo == tpm.HashAlgo_SHA256 {
		for _, v := range strings.Split(expectedPCRMap, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in parsing %s", v)
				}
				hexEncodedPCR, err := hex.DecodeString(entry[1])
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in encoding %s", v)
				}
				pcrMap[uint32(uv)] = hexEncodedPCR
				hsh.Write(hexEncodedPCR)
			} else {
				return nil, nil, fmt.Errorf(" PCR key:value is invalid %s", v)
			}
		}
	} else {
		return nil, nil, fmt.Errorf("Unknown Hash Algorithm for TPM PCRs %v", algo)
	}
	if len(pcrMap) == 0 {
		return nil, nil, fmt.Errorf(" PCRMap is null")
	}
	return pcrMap, hsh.Sum(nil), nil
}

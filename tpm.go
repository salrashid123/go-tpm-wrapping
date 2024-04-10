package tpm

import (
	"crypto/aes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmrand "github.com/salrashid123/tpmrand"
	context "golang.org/x/net/context"
	"google.golang.org/protobuf/proto"
)

const (
	EnvTPMPath = "TPM_PATH"
	EnvPCRS    = "TPM_PCRS"
)

const (
	TPMEncrypt = iota
)

const (
	WrapperTypeTPM wrapping.WrapperType = "tpm"
)

// Configures and manages the TPM SRK encryption wrapper
//
//	Values here are set using setConfig or options
type Wrapper struct {
	tpmPath      string
	pcrs         string
	userAgent    string
	currentKeyId *atomic.Value
}

var (
	_ wrapping.Wrapper = (*Wrapper)(nil)
)

// Initialize a TPM based encryption wrapper
func NewWrapper() *Wrapper {
	s := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	s.currentKeyId.Store("")
	return s
}

// Set the configuration options
func (s *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
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

	// Map that holds non-sensitive configuration info to return
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["tpm_path"] = s.tpmPath
	wrapConfig.Metadata["pcrs"] = s.pcrs
	return wrapConfig, nil
}

func (s *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return WrapperTypeTPM, nil
}

func (s *Wrapper) KeyId(_ context.Context) (string, error) {
	return s.currentKeyId.Load().(string), nil
}

// Encrypts data using a TPM's Storage Root Key (SRK)
func (s *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	rwc, err := tpm2.OpenTPM(s.tpmPath)
	if err != nil {
		return nil, fmt.Errorf("can't open TPM %q: %v", s.tpmPath, err)
	}
	defer rwc.Close()

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	var pcrList = []int{}
	if s.pcrs != "" {
		strpcrs := strings.Split(s.pcrs, ",")
		for _, i := range strpcrs {
			j, err := strconv.Atoi(i)
			if err != nil {
				return nil, fmt.Errorf("error converting pcr string %v", err)
			}
			pcrList = append(pcrList, j)
		}
	}

	// Note, we only use the "current" values of the PCRs specified
	// a TODO could be to use a user-supplied list of values
	// [client.SealOpts](https://pkg.go.dev/github.com/google/go-tpm-tools/client#SealOpts)
	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	sOpt := client.SealOpts{
		Current: sel,
	}

	srk, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		return nil, fmt.Errorf("can't create srk from template: %v", err)
	}
	defer srk.Close()

	sealed, err := srk.Seal([]byte(env.Key), sOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to seal: %v", err)
	}
	encrypted, err := proto.Marshal(sealed)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SealedBytes: %v", err)
	}
	keyName, err := srk.Name().Digest.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to get keyName: %v", err)
	}
	// Store current key id value
	s.currentKeyId.Store(hex.EncodeToString(keyName))

	r, err := tpmrand.NewTPMRand(&tpmrand.Reader{
		TpmDevice: rwc,
		//Scheme:    backoff.NewConstantBackOff(time.Millisecond * 10),
	})

	iv := make([]byte, aes.BlockSize)
	// or to use the random source from the tpm itself: https://github.com/salrashid123/tpmrand
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, errors.New("error creating initialization vector")
	}

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  TPMEncrypt,
			KeyId:      hex.EncodeToString(keyName),
			WrappedKey: encrypted,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext.
func (s *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in.Ciphertext == nil {
		return nil, fmt.Errorf("given ciphertext for decryption is nil")
	}

	rwc, err := tpm2.OpenTPM(s.tpmPath)
	if err != nil {
		return nil, fmt.Errorf("can't open TPM %q: %v", s.tpmPath, err)
	}
	defer rwc.Close()

	// Default to mechanism used before key info was stored
	if in.KeyInfo == nil {
		in.KeyInfo = &wrapping.KeyInfo{
			Mechanism: TPMEncrypt,
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

	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	var plaintext []byte
	switch in.KeyInfo.Mechanism {
	case TPMEncrypt:
		srk, err := client.StorageRootKeyRSA(rwc)
		if err != nil {
			return nil, fmt.Errorf("error  loading  srk %v\n", err)
		}
		defer srk.Close()

		sealed := &tpm.SealedBytes{}
		err = proto.Unmarshal(in.KeyInfo.WrappedKey, sealed)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshall key: %w", err)
		}

		decrypted, err := srk.Unseal(sealed, client.UnsealOpts{
			CertifyCurrent: sel,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to unsealing key: %w", err)
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

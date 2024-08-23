package tpmwrap

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrappb "github.com/salrashid123/go-tpm-wrapping/tpmwrappb"
	tpmrand "github.com/salrashid123/tpmrand"
	context "golang.org/x/net/context"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	WrapperTypeTPM wrapping.WrapperType = "tpm"
)

// Configures and manages the TPM SRK encryption wrapper
//
//	Values here are set using setConfig or options
type TPMWrapper struct {
	tpmPath              string
	tpmDevice            io.ReadWriteCloser
	pcrValues            string
	userAuth             string
	hierarchyAuth        string
	userAgent            string
	currentKeyId         *atomic.Value
	keyName              string
	encryptingPublicKey  string
	encryptedSessionName string
	debug                bool
}

var (
	_ wrapping.Wrapper = (*TPMWrapper)(nil)
)

// Initialize a TPM based encryption wrapper
func NewWrapper() *TPMWrapper {

	s := &TPMWrapper{
		currentKeyId: new(atomic.Value),
	}
	s.currentKeyId.Store("")
	return s
}

// Set the configuration options
func (s *TPMWrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
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
	case os.Getenv(EnvUserAuth) != "" && !opts.Options.WithDisallowEnvVars:
		s.userAuth = os.Getenv(EnvUserAuth)
	case opts.withUserAuth != "":
		s.userAuth = opts.withUserAuth
	}

	switch {
	case os.Getenv(EnvHierarchyAuth) != "" && !opts.Options.WithDisallowEnvVars:
		s.hierarchyAuth = os.Getenv(EnvHierarchyAuth)
	case opts.withHierarchyAuth != "":
		s.hierarchyAuth = opts.withHierarchyAuth
	}

	switch {
	case os.Getenv(EnvKeyName) != "" && !opts.Options.WithDisallowEnvVars:
		s.keyName = os.Getenv(EnvKeyName)
	case opts.withKeyName != "":
		s.keyName = opts.withKeyName
	}

	switch {
	case os.Getenv(EnvPCRValues) != "" && !opts.Options.WithDisallowEnvVars:
		s.pcrValues = os.Getenv(EnvPCRValues)
	case opts.withPCRValues != "":
		s.pcrValues = opts.withPCRValues
	}

	switch {
	case os.Getenv(EnvTPMPath) != "" && !opts.Options.WithDisallowEnvVars:
		s.tpmPath = os.Getenv(EnvTPMPath)
	case opts.withTPMPath != "":
		s.tpmPath = opts.withTPMPath
	}

	switch {
	case os.Getenv(EnvEncryptingPublicKey) != "" && !opts.Options.WithDisallowEnvVars:
		s.encryptingPublicKey = os.Getenv(EnvEncryptingPublicKey)
	case opts.withEncryptingPublicKey != "":
		s.encryptingPublicKey = opts.withEncryptingPublicKey
	}

	switch {
	case os.Getenv(EnvSessionEncryptionName) != "" && !opts.Options.WithDisallowEnvVars:
		s.encryptedSessionName = os.Getenv(EnvSessionEncryptionName)
	case opts.withSessionEncryptionName != "":
		s.encryptedSessionName = opts.withSessionEncryptionName
	}

	if opts.withTPM != nil {
		if s.tpmPath != "" {
			return nil, fmt.Errorf("cannot specify both TPMPath and TPMDevice")
		}
		s.tpmDevice = opts.withTPM
	}

	s.debug = opts.withDebug

	// Map that holds non-sensitive configuration info to return
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata[TPM_PATH] = s.tpmPath
	wrapConfig.Metadata[PCR_VALUES] = s.pcrValues
	wrapConfig.Metadata[USER_AUTH] = s.userAuth
	wrapConfig.Metadata[HIERARCHY_AUTH] = s.hierarchyAuth
	wrapConfig.Metadata[KEY_NAME] = s.keyName
	wrapConfig.Metadata[SESSION_ENCRYPTION_NAME] = s.encryptedSessionName
	return wrapConfig, nil
}

func (s *TPMWrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return WrapperTypeTPM, nil
}

func (s *TPMWrapper) KeyId(_ context.Context) (string, error) {
	return s.currentKeyId.Load().(string), nil
}

// Encrypts data using a TPM's Storage Root Key (SRK)
func (s *TPMWrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	if s.debug {
		fmt.Printf("Encrypting with name %s\n", s.keyName)
	}

	var rwc io.ReadWriteCloser
	if s.tpmDevice != nil {
		rwc = s.tpmDevice
	} else {
		var err error
		rwc, err = openTPM(s.tpmPath)
		if err != nil {
			return nil, fmt.Errorf("can't open TPM %q: %v", s.tpmPath, err)
		}
		defer rwc.Close()
	}
	rwr := transport.FromReadWriter(rwc)

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	encsess := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut))
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: encsess.Handle(),
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// TODO: add parameter for setup an AuthHandle with password incase the Endorsement needs a password
	createEKRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr, encsess)
	if err != nil {
		return nil, fmt.Errorf("error creating EK Primary  %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	if s.encryptedSessionName != "" {
		if s.encryptedSessionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			return nil, fmt.Errorf("session encryption names do not match expected [%s] got [%s]", s.encryptedSessionName, hex.EncodeToString(createEKRsp.Name.Buffer))
		}
	}

	encryptionPub, err := createEKRsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("error getting session encryption public contents %v", err)
	}

	rsessInOut := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub))

	defer func() {
		flushContextInOut := tpm2.FlushContext{
			FlushHandle: rsessInOut.Handle(),
		}
		_, _ = flushContextInOut.Execute(rwr)
	}()

	// get the specified pcrs
	pcrMap, pcrList, pcrHash, err := getPCRMap(tpm2.TPMAlgSHA256, s.pcrValues)
	if err != nil {
		return nil, fmt.Errorf(" Could not get PCRMap: %s", err)
	}

	// create an H2 primary; this is just for convenience. you could create any primary with auth
	//  i'm just doing this so i can easily specify a keyfile.  A todo would be to set a owner/primary auth
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth([]byte(s.hierarchyAuth)),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr, rsessInOut)
	if err != nil {
		return nil, fmt.Errorf("can't create primary %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub)}...)
	if err != nil {
		return nil, fmt.Errorf("setting up trial session: %v", err)
	}
	defer func() {
		if err := cleanup1(); err != nil {
			fmt.Printf("cleaning up trial session: %v", err)
		}
	}()

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			},
		},
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: pcrHash,
		},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("error executing PolicyPCR: %v", err)
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("executing PolicyAuthValue: %v", err)
	}

	// now that we have the pcr's set, get its digest
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("error executing PolicyGetDigest: %v", err)
	}

	cCreate, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:       tpm2.TPMAlgKeyedHash,
			NameAlg:    tpm2.TPMAlgSHA256,
			AuthPolicy: pgd.PolicyDigest, // set the pcr auth policy
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true, // allow policy based auth
			},
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: []byte(env.Key), //  set the inner encryption key as the sensitive data
				}),
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(s.userAuth), // set the key auth password
				},
			},
		},
	}.Execute(rwr, rsessInOut)
	if err != nil {
		return nil, fmt.Errorf("can't create object TPM  %v", err)
	}

	// now load the key
	aKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: cPrimary.ObjectHandle,
			Name:   cPrimary.Name,
		},
		InPrivate: cCreate.OutPrivate,
		InPublic:  cCreate.OutPublic,
	}.Execute(rwr, rsessInOut)
	if err != nil {
		return nil, fmt.Errorf("can't load object  %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: aKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	// create a keyfile representation (eg, a PEM format for the TPM based sealing key)
	tkf := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		cCreate.OutPublic,
		cCreate.OutPrivate,
		keyfile.WithParent(tpm2.TPMHandle(tpm2.TPMRHOwner)),
		keyfile.WithUserAuth([]byte(s.userAuth)),
		keyfile.WithDescription(s.keyName),
	)

	kfb := new(bytes.Buffer)
	err = keyfile.Encode(kfb, tkf)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Key: %v", err)
	}

	var pr []*tpmwrappb.PCRS
	for i, k := range pcrMap {
		pr = append(pr, &tpmwrappb.PCRS{
			Pcr:   int32(i),
			Value: k,
		})
	}
	hasUserAuth := false

	if s.userAuth != "" {
		hasUserAuth = true
	}
	wrappb := &tpmwrappb.Secret{
		Name:     s.keyName,
		Type:     tpmwrappb.Secret_SEALED,
		Pcrs:     pr,
		UserAuth: hasUserAuth,
		Key: &tpmwrappb.Secret_SealedOp{
			&tpmwrappb.SealedKey{
				Keyfile: kfb.Bytes(),
			},
		},
	}

	b, err := protojson.Marshal(wrappb)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap proto Key: %v", err)
	}

	// Store current key id value
	s.currentKeyId.Store(s.keyName)

	// get the initialization vector
	if len(env.Iv) == 0 {
		r, err := tpmrand.NewTPMRand(&tpmrand.Reader{
			TpmDevice: rwc,
			//Scheme:    backoff.NewConstantBackOff(time.Millisecond * 10),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to tpmrandreader: %v", err)
		}
		env.Iv = make([]byte, aes.BlockSize)
		// or to use the random source from the tpm itself: https://github.com/salrashid123/tpmrand
		if _, err := io.ReadFull(r, env.Iv); err != nil {
			return nil, errors.New("error creating initialization vector")
		}
	}

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  TPMSeal,
			KeyId:      s.keyName, //  hex.EncodeToString(aKey.Name.Buffer),
			WrappedKey: b,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext.
func (s *TPMWrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in.Ciphertext == nil {
		return nil, fmt.Errorf("given ciphertext for decryption is nil")
	}

	var rwc io.ReadWriteCloser
	if s.tpmDevice != nil {
		rwc = s.tpmDevice
	} else {
		var err error
		rwc, err = openTPM(s.tpmPath)
		if err != nil {
			return nil, fmt.Errorf("can't open TPM %q: %v", s.tpmPath, err)
		}
		defer rwc.Close()
	}
	rwr := transport.FromReadWriter(rwc)

	// Default to mechanism used before key info was stored
	if in.KeyInfo == nil {
		in.KeyInfo = &wrapping.KeyInfo{
			Mechanism: TPMSeal,
		}
	}

	// first setup session encryption with the EK
	encsess := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut))
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: encsess.Handle(),
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// TODO: add parameter for setup an AuthHandle with password incase the Endorsement needs a password
	createEKRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr, encsess)
	if err != nil {
		return nil, fmt.Errorf("error creating EK Primary  %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	if s.encryptedSessionName != "" {
		if s.encryptedSessionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			return nil, fmt.Errorf("session encryption names do not match expected [%s] got [%s]", s.encryptedSessionName, hex.EncodeToString(createEKRsp.Name.Buffer))
		}
	}

	encryptionPub, err := createEKRsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("error getting session encryption public contents %v", err)
	}

	rsessInOut := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub))

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsessInOut.Handle(),
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// create H2 template again
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth([]byte(s.hierarchyAuth)),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr, rsessInOut)
	if err != nil {
		return nil, fmt.Errorf("can't create primary %v", err)
	}
	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, err = flush.Execute(rwr)
	}()

	var plaintext []byte
	switch in.KeyInfo.Mechanism {
	case TPMSeal:

		wrappb := &tpmwrappb.Secret{}
		err := protojson.Unmarshal(in.KeyInfo.WrappedKey, wrappb)
		if err != nil {
			return nil, fmt.Errorf("failed to unwrap proto Key: %v", err)
		}

		if s.debug {
			fmt.Printf("Decrypting with name %s\n", wrappb.Name)
		}

		var pcrList []uint
		for _, v := range wrappb.Pcrs {
			pcrList = append(pcrList, uint(v.Pcr))
			if s.debug {
				fmt.Printf("Key encoded with PCR: %d %s\n", v.Pcr, hex.EncodeToString(v.Value))
			}
		}

		if s.debug {
			fmt.Printf("Key has password %t\n", wrappb.UserAuth)
		}

		if wrappb.Type != tpmwrappb.Secret_SEALED {
			return nil, fmt.Errorf("incorrect keytype, expected Secret_SEALED")
		}

		pbk, ok := wrappb.GetKey().(*tpmwrappb.Secret_SealedOp)
		if !ok {
			return nil, fmt.Errorf("error unmarshalling tpmwrappb.Secret_SealedOp")
		}

		// the wrappedkey is actually the PEM format of the key we used to seal
		regenKey, err := keyfile.Decode(pbk.SealedOp.Keyfile)
		if err != nil {
			return nil, fmt.Errorf("error decrypting regenerated key: %w", err)
		}

		// now load the key
		k, err := tpm2.Load{
			ParentHandle: tpm2.NamedHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
			},
			InPublic:  regenKey.Pubkey,
			InPrivate: regenKey.Privkey,
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("executing Load: %v", err)
		}
		defer func() {
			flush := tpm2.FlushContext{
				FlushHandle: k.ObjectHandle,
			}
			_, err = flush.Execute(rwr)
		}()

		// create a pcr policy along with PolicyAuth Value (to account for a password)
		// remember to set the userAuth into the auth option into the policy session (which'll include it in the final auth calculation)
		sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(s.userAuth)), tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub)}...)
		if err != nil {
			return nil, fmt.Errorf("setting up policy session: %v", err)
		}
		defer cleanup2()

		sel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
				},
			},
		}

		_, err = tpm2.PolicyPCR{
			PolicySession: sess2.Handle(),

			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("executing PolicyPCR: %v", err)
		}

		_, err = tpm2.PolicyAuthValue{
			PolicySession: sess2.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("executing PolicyAuthValue: %v", err)
		}

		// use this policy to unseal the data
		unsealresp, err := tpm2.Unseal{
			ItemHandle: tpm2.AuthHandle{
				Handle: k.ObjectHandle,
				Name:   k.Name,
				Auth:   sess2,
			},
		}.Execute(rwr) // since we're using an encrypted session already (sess2),  the transmitted data is also encrypted
		if err != nil {
			return nil, fmt.Errorf("executing unseal: %v", err)
		}

		// the unsealed data is the inner encryption key
		envInfo := &wrapping.EnvelopeInfo{
			Key:        unsealresp.OutData.Buffer,
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

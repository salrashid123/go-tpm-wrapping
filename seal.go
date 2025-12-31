package tpmwrap

import (
	"bytes"
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
	wrapConfig.Metadata[PCR_VALUES] = s.pcrValues
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

	// first encrypt the plaintext using the underlying wrapping library construct
	//  this will by default generate a random encryption key, iv and use that to generate a ciphertext
	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	// get the endorsement key for the local TPM which we will use for parameter encryption
	createEKRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("error creating EK Primary  %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// if the user provided as encryption session "name" in hex, compare that to the one we just got
	if s.encryptedSessionName != "" {
		if s.encryptedSessionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			return nil, fmt.Errorf("session encryption names do not match expected [%s] got [%s]", s.encryptedSessionName, hex.EncodeToString(createEKRsp.Name.Buffer))
		}
	}

	// now get the encryption session's name
	encryptionPub, err := createEKRsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("error getting session encryption public contents %v", err)
	}

	// create a full encryption session for rest of the operations
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

	// now create a session to setup the keys.  For each, operation, pass the encryption session public as the salt
	// this session will setup the pcr digest and password (policy)
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

	// now that we have the digest, create the actual TPM based key based on the parent
	// remember the sensitive data **is** the encryption we we used in wrapping.EnvelopeEncrypt(plaintext, opt...)
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
				UserWithAuth: false,
			},
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: []byte(env.Key), //  <<<<<<<<<<<<<<<<< set the inner encryption key as the sensitive data
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

	// get the keyfiles PEM bytes
	kfb := new(bytes.Buffer)
	err = keyfile.Encode(kfb, tkf)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Key: %v", err)
	}

	// get the list of PCRs and their values we used
	// this isn't necessary but i'm encoding it into the proto incase
	// we want a reference of "what were the pcr values we even used to encrypt this"
	// is ever needed.   I'm on the fence if this is even needed (probably not)
	var pr []*tpmwrappb.PCRS
	for i, k := range pcrMap {
		pr = append(pr, &tpmwrappb.PCRS{
			Pcr:   int32(i),
			Value: k,
		})
	}

	// create the proto format of wrapped key and values
	hasUserAuth := false
	if s.userAuth != "" {
		hasUserAuth = true
	}
	wrappb := &tpmwrappb.Secret{
		Name:     s.keyName,
		Version:  KEY_VERSION,
		Type:     tpmwrappb.Secret_SEALED,
		Pcrs:     pr,
		UserAuth: hasUserAuth,
		Key: &tpmwrappb.Secret_SealedOp{
			&tpmwrappb.SealedKey{
				Keyfile: string(kfb.Bytes()),
			},
		},
	}

	// get the bytes of the proto
	b, err := protojson.Marshal(wrappb)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap proto Key: %v", err)
	}

	// Store current key id value
	s.currentKeyId.Store(s.keyName)

	// return the ciphertext, IV used and the bytes of the proto as the actaul
	// sealed key.  The sealed key includes the TPM KEY that has the sealed key that was used
	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  TPMSeal,
			KeyId:      s.keyName,
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

	// first setup basis session encryption with the EK
	encsess := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut))
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: encsess.Handle(),
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// get the local endorsement key using the basic session
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

	// compare if the user sent in a session "name" to what we just got
	if s.encryptedSessionName != "" {
		if s.encryptedSessionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			return nil, fmt.Errorf("session encryption names do not match expected [%s] got [%s]", s.encryptedSessionName, hex.EncodeToString(createEKRsp.Name.Buffer))
		}
	}

	// get the EKPub
	encryptionPub, err := createEKRsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("error getting session encryption public contents %v", err)
	}

	// use the ekpub to create a full session encryption handle
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

		// decode the inner proto from
		wrappb := &tpmwrappb.Secret{}
		err := protojson.Unmarshal(in.KeyInfo.WrappedKey, wrappb)
		if err != nil {
			return nil, fmt.Errorf("failed to unwrap proto Key: %v", err)
		}

		if wrappb.Version != KEY_VERSION {
			return nil, fmt.Errorf("key is encoded by key version [%d] which is incompatile with the current version [%d]", wrappb.Version, KEY_VERSION)
		}

		if s.debug {
			fmt.Printf("Decrypting with name %s\n", wrappb.Name)
		}

		// get a list of the pcr's used in the sealing
		var pcrList []uint
		var pcrDigest []byte
		if s.pcrValues != "" {
			var l map[uint][]byte
			l, pcrList, pcrDigest, err = getPCRMap(tpm2.TPMAlgSHA256, s.pcrValues)
			if err != nil {
				return nil, fmt.Errorf(" error parsing pcrmap: %v", err)
			}
			if s.debug {
				fmt.Printf("PCRList provided with command line: %v \n", l)
			}
		} else {
			for _, v := range wrappb.Pcrs {
				pcrList = append(pcrList, uint(v.Pcr))
				if s.debug {
					fmt.Printf("Key encoded with PCR: %d %s\n", v.Pcr, hex.EncodeToString(v.Value))
				}
			}
		}
		sel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
				},
			},
		}
		if s.debug {
			fmt.Printf("Key has password %t\n", wrappb.UserAuth)
		}

		if wrappb.Type != tpmwrappb.Secret_SEALED {
			return nil, fmt.Errorf("incorrect keytype, expected Secret_SEALED")
		}

		// now decode the keyfile
		pbk, ok := wrappb.GetKey().(*tpmwrappb.Secret_SealedOp)
		if !ok {
			return nil, fmt.Errorf("error unmarshalling tpmwrappb.Secret_SealedOp")
		}

		// the wrappedkey is actually the PEM format of the key we used to seal
		regenKey, err := keyfile.Decode([]byte(pbk.SealedOp.Keyfile))
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

		_, err = tpm2.PolicyPCR{
			PolicySession: sess2.Handle(),
			PcrDigest:     tpm2.TPM2BDigest{Buffer: pcrDigest},
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

		// we're finally ready to decrypt the ciphertext
		plaintext, err = wrapping.EnvelopeDecrypt(envInfo, opt...)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data with envelope: %w", err)
		}

	default:
		return nil, fmt.Errorf("invalid mechanism: %d", in.KeyInfo.Mechanism)
	}

	return plaintext, nil
}

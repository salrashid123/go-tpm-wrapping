package tpmwrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrappb "github.com/salrashid123/go-tpm-wrapping/tpmwrappb"
	tpmrand "github.com/salrashid123/tpmrand"
	context "golang.org/x/net/context"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	WrapperTypeRemoteTPM wrapping.WrapperType = "tpmimport"
)

// Configures and manages the TPM SRK encryption wrapper
//
//	Values here are set using setConfig or options
type RemoteWrapper struct {
	tpmPath              string
	tpmDevice            io.ReadWriteCloser
	userAgent            string
	userAuth             string
	hierarchyAuth        string
	currentKeyId         *atomic.Value
	pcrValues            string
	encryptingPublicKey  string
	encryptedSessionName string
	keyName              string
	debug                bool
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
	case os.Getenv(EnvSessionEncryptionName) != "" && !opts.Options.WithDisallowEnvVars:
		s.encryptedSessionName = os.Getenv(EnvSessionEncryptionName)
	case opts.withSessionEncryptionName != "":
		s.encryptedSessionName = opts.withSessionEncryptionName
	}

	s.debug = opts.withDebug

	// Map that holds non-sensitive configuration info to return
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata[TPM_PATH] = s.tpmPath
	wrapConfig.Metadata[PCR_VALUES] = s.pcrValues
	wrapConfig.Metadata[ENCRYPTING_PUBLIC_KEY] = s.encryptingPublicKey
	wrapConfig.Metadata[USER_AUTH] = s.userAuth
	wrapConfig.Metadata[HIERARCHY_AUTH] = s.hierarchyAuth
	wrapConfig.Metadata[KEY_NAME] = s.keyName
	wrapConfig.Metadata[SESSION_ENCRYPTION_NAME] = s.encryptedSessionName
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

	if s.debug {
		fmt.Printf("Encrypting with name %s\n", s.keyName)
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	if s.userAuth != "" && s.pcrValues != "" {
		return nil, fmt.Errorf("both userAuth and PCR policies currently not supported.  Set either userAuth or pcrs")
	}

	// first read the ekpub value and get its "name"
	if s.encryptingPublicKey == "" {
		return nil, fmt.Errorf("encrypting public key must be set")
	}

	pubPEMData, err := hex.DecodeString(s.encryptingPublicKey)
	if err != nil {
		return nil, fmt.Errorf(" error decoding public key  : %v", err)
	}

	block, _ := pem.Decode(pubPEMData)
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(" unable parsing encrypting public key : %v", err)
	}

	rsaPub, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf(" error converting encryptingPublicKey to rsa")
	}

	ekPububFromPEMTemplate := tpm2.RSAEKTemplate

	ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
		tpm2.TPMAlgRSA,
		&tpm2.TPM2BPublicKeyRSA{
			Buffer: rsaPub.N.Bytes(),
		},
	)

	ekName, err := tpm2.ObjectName(&ekPububFromPEMTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to get name key: %v", err)
	}

	if s.debug {
		fmt.Printf("EK Name %s\n", hex.EncodeToString(ekName.Buffer))
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

	rsessInOut := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut))

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsessInOut.Handle(),
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// create a generic local primary key
	cPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.HandleName(tpm2.TPMRHOwner),
			Auth:   tpm2.PasswordAuth([]byte(s.hierarchyAuth)),
		},
		InPublic: tpm2.New2B(tpm2.RSASRKTemplate), // tpm2.New2B(ECCSRKHTemplate),
	}.Execute(rwr, rsessInOut)
	if err != nil {
		return nil, fmt.Errorf("can't  CreatePrimary %v", err)
	}

	defer func() {
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, _ = flush.Execute(rwr)
	}()

	var kek []byte
	var dupPub []byte
	var dupDup []byte
	var dupSeed []byte

	// create an initialization vector for the inner TPM based AES key
	iv := make([]byte, aes.BlockSize)
	// _, err = io.ReadFull(rand.Reader, iv)
	// if err != nil {
	// 	return nil, fmt.Errorf("can't create IV %v", err)
	// }

	r, err := tpmrand.NewTPMRand(&tpmrand.Reader{
		TpmDevice:        rwc,
		EncryptionHandle: createEKRsp.ObjectHandle,
		EncryptionPub:    encryptionPub,
	})
	if err != nil {
		return nil, fmt.Errorf("can't create tpmrandom generator %v", err)
	}

	_, err = io.ReadFull(r, iv)
	if err != nil {
		return nil, fmt.Errorf("can't create IV %v", err)
	}

	// get the pcr values specified to bind against
	pcrMap, pcrs, pcrHash, err := getPCRMap(tpm2.TPMAlgSHA256, s.pcrValues)
	if err != nil {
		return nil, fmt.Errorf(" Could not get PCRMap: %s", err)
	}

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}

	// if we have pcrValues set, then we're using PCRPolicy, otherwise userAuth
	if s.pcrValues != "" {

		// first create any random per-use AES key in memory
		primarySensitive := make([]byte, aes.BlockSize)
		// if _, err := io.ReadFull(rand.Reader, primarySensitive); err != nil {
		// 	return nil, fmt.Errorf("error creating inner key %v", err)
		// }

		_, err = io.ReadFull(r, primarySensitive)
		if err != nil {
			return nil, fmt.Errorf("can't create IV %v", err)
		}

		// create a TPM-based AES key and specify its to be the per-use AES key.
		//  We're first using a plain aes.NewCFBEncrypter() to wrap env.Key because
		//  we probably can't use the local TPM's to encrypt since its PCRs may not
		//  match what we need on the target TPM (i.e, the local and target TPM's PCRs may not match)
		byteMsg := []byte(env.Key)
		block, err := aes.NewCipher(primarySensitive)
		if err != nil {
			return nil, fmt.Errorf("could not create new cipher: %v", err)
		}
		cipherTextWithIV := make([]byte, aes.BlockSize+len(byteMsg))
		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(cipherTextWithIV[aes.BlockSize:], byteMsg)

		kek = cipherTextWithIV[aes.BlockSize:]

		if s.debug {
			fmt.Printf("Encrypted Kek %s\n", hex.EncodeToString(kek))
		}

		// at this point, we need to create a new key with the same per-use AES key
		// but this one has an auth policy set to PCRs and used for duplication

		// create a pcr trial session to get its digest
		pcr_sess_trial, pcr_sess_trial_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub)}...)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer pcr_sess_trial_cleanup()

		if s.debug {
			fmt.Printf("PCR Hash: %s\n", hex.EncodeToString(pcrHash))
		}
		_, err = tpm2.PolicyPCR{
			PolicySession: pcr_sess_trial.Handle(),
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

		// read the digest
		pcrpgd, err := tpm2.PolicyGetDigest{
			PolicySession: pcr_sess_trial.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicyGetDigest: %v", err)
		}
		err = pcr_sess_trial_cleanup()
		if err != nil {
			return nil, fmt.Errorf("error purging session: %v", err)
		}

		// create a trial session with PolicyDuplicationSelect which stipulates the target systems
		// where this key can get duplicated
		dupselect_sess_trial, dupselect_trial_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub)}...)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer dupselect_trial_cleanup()

		_, err = tpm2.PolicyDuplicationSelect{
			PolicySession: dupselect_sess_trial.Handle(),
			NewParentName: *ekName,
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error setting policy duplicationSelect %v", err)
		}

		// get its digest
		dupselpgd, err := tpm2.PolicyGetDigest{
			PolicySession: dupselect_sess_trial.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicyGetDigest: %v", err)
		}
		err = dupselect_trial_cleanup()
		if err != nil {
			return nil, fmt.Errorf("error purging session: %v", err)
		}

		//

		// create an OR policy which includes the PolicyPCR and PolicyDuplicationSelect digests
		or_sess_trial, or_sess_tiral_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub)}...)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer or_sess_tiral_cleanup()

		_, err = tpm2.PolicyOr{
			PolicySession: or_sess_trial.Handle(),
			PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd.PolicyDigest}},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error setting policyOR %v", err)
		}

		// calculate the OR hash
		or_trial_digest, err := tpm2.PolicyGetDigest{
			PolicySession: or_sess_trial.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicyGetDigest: %v", err)
		}
		err = or_sess_tiral_cleanup()
		if err != nil {
			return nil, fmt.Errorf("error purging session: %v", err)
		}

		// create a new key with the same sensitive data but for this, set the AuthPolicy to the policyOR
		createLoadedRespNew, err := tpm2.CreateLoaded{
			ParentHandle: tpm2.AuthHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
				Auth:   tpm2.PasswordAuth([]byte(s.hierarchyAuth)),
			},
			InPublic: tpm2.New2BTemplate(&tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgSymCipher,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:            false,
					FixedParent:         false,
					UserWithAuth:        false,
					SensitiveDataOrigin: false, // set false since w'ere setting the sensitive
					Decrypt:             true,
					SignEncrypt:         true,
				},
				AuthPolicy: tpm2.TPM2BDigest{Buffer: or_trial_digest.PolicyDigest.Buffer}, // PolicyOr digest
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPMSSymCipherParms{
						Sym: tpm2.TPMTSymDefObject{
							Algorithm: tpm2.TPMAlgAES,
							Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
							KeyBits: tpm2.NewTPMUSymKeyBits(
								tpm2.TPMAlgAES,
								tpm2.TPMKeyBits(128),
							),
						},
					},
				),
			}),
			InSensitive: tpm2.TPM2BSensitiveCreate{
				Sensitive: &tpm2.TPMSSensitiveCreate{
					Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
						Buffer: primarySensitive, // the per-use key
					}),
				},
			},
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("can't create encryption key %v", err)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: createLoadedRespNew.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		// clear the primary, we don't need it anymore
		flushPrimaryContextCmd := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, _ = flushPrimaryContextCmd.Execute(rwr)

		// load the target EK
		newParentLoad, err := tpm2.LoadExternal{
			Hierarchy: tpm2.TPMRHOwner,
			InPublic:  tpm2.New2B(ekPububFromPEMTemplate),
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf(" newParentLoadcmd load  %v", err)
		}

		// setup a real session with just PolicyDuplicationSelect
		or_sess, aor_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub)}...)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer aor_cleanup()

		_, err = tpm2.PolicyDuplicationSelect{
			PolicySession: or_sess.Handle(),
			NewParentName: newParentLoad.Name,
			ObjectName:    createLoadedRespNew.Name,
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error setting  PolicyDuplicationSelect %v", err)
		}

		dupselpgd2, err := tpm2.PolicyGetDigest{
			PolicySession: or_sess.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicyGetDigest: %v", err)
		}

		// calculate the OR policy using the digest for the PCR and the "real" sessions PolicyDuplicationSelect value
		_, err = tpm2.PolicyOr{
			PolicySession: or_sess.Handle(),
			PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd2.PolicyDigest}},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error setting policy PolicyOr %v", err)
		}

		// create the duplicate but set the Auth to the real policy.  Since we used PolicyDuplicationSelect, the
		//  auth will get fulfilled
		duplicateResp, err := tpm2.Duplicate{
			ObjectHandle: tpm2.AuthHandle{
				Handle: createLoadedRespNew.ObjectHandle,
				Name:   createLoadedRespNew.Name,
				Auth:   or_sess,
			},
			NewParentHandle: tpm2.NamedHandle{
				Handle: newParentLoad.ObjectHandle,
				Name:   newParentLoad.Name,
			},
			Symmetric: tpm2.TPMTSymDef{
				Algorithm: tpm2.TPMAlgNull,
			},
		}.Execute(rwr) // no need to set rsessInOut since the session is encrypted
		if err != nil {
			return nil, fmt.Errorf("duplicateResp can't crate duplicate %v", err)
		}

		// generate the bytes for the duplication
		dupPub = createLoadedRespNew.OutPublic.Bytes()
		dupSeed = duplicateResp.OutSymSeed.Buffer
		dupDup = duplicateResp.Duplicate.Buffer

	} else {

		// userAuth
		// first create a trial session which uses PolicyDuplicationSelect to bind
		// the duplication to eh ekPub of the remote TPM
		sess, session1cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub)}...)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer session1cleanup()

		// _, err = tpm2.PolicyCommandCode{
		// 	PolicySession: sess.Handle(),
		// 	Code:          tpm2.TPMCCDuplicate,
		// }.Execute(rwr)
		// if err != nil {
		// 	return nil, fmt.Errorf("Error setting policy commandcode %v", err)
		// }

		_, err = tpm2.PolicyDuplicationSelect{
			PolicySession: sess.Handle(),
			NewParentName: *ekName,
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error setting policy PolicyDuplicationSelect %v", err)
		}

		pgd, err := tpm2.PolicyGetDigest{
			PolicySession: sess.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicyGetDigest: %v", err)
		}

		// create an AES key bound with this authPolicy
		createLoadedResp, err := tpm2.CreateLoaded{
			ParentHandle: tpm2.AuthHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
				Auth:   tpm2.PasswordAuth(nil),
			},
			InPublic: tpm2.New2BTemplate(&tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgSymCipher,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:            false,
					FixedParent:         false,
					UserWithAuth:        true,
					SensitiveDataOrigin: true,
					Decrypt:             true,
					SignEncrypt:         true,
				},
				AuthPolicy: tpm2.TPM2BDigest{Buffer: pgd.PolicyDigest.Buffer}, // auth policy with PolicyDuplicationSelect
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPMSSymCipherParms{
						Sym: tpm2.TPMTSymDefObject{
							Algorithm: tpm2.TPMAlgAES,
							Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
							KeyBits: tpm2.NewTPMUSymKeyBits(
								tpm2.TPMAlgAES,
								tpm2.TPMKeyBits(128),
							),
						},
					},
				),
			}),
			InSensitive: tpm2.TPM2BSensitiveCreate{
				Sensitive: &tpm2.TPMSSensitiveCreate{
					UserAuth: tpm2.TPM2BAuth{
						Buffer: []byte(s.userAuth), // set any userAuth
					},
				},
			},
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("can't create encryption key %v", err)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: createLoadedResp.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		if s.debug {
			fmt.Printf("Loaded Name %s\n", hex.EncodeToString(createLoadedResp.Name.Buffer))
		}
		// flush parent
		flush := tpm2.FlushContext{
			FlushHandle: cPrimary.ObjectHandle,
		}
		_, _ = flush.Execute(rwr)

		// load the remote EKPub
		newParentLoadcmd := tpm2.LoadExternal{
			Hierarchy: tpm2.TPMRHOwner,
			InPublic:  tpm2.New2B(ekPububFromPEMTemplate),
		}

		rsp, err := newParentLoadcmd.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf(" newParentLoadcmd can't close TPM  %v", err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: rsp.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		// now do the duplication, remember to set the auth policy callback to PolicyDuplicationSelect.

		// this will fulfill the conditions we set earlier
		duplicateResp, err := tpm2.Duplicate{
			ObjectHandle: tpm2.AuthHandle{
				Handle: createLoadedResp.ObjectHandle,
				Name:   createLoadedResp.Name,
				Auth: tpm2.Policy(tpm2.TPMAlgSHA256, 16, tpm2.PolicyCallback(func(tpm transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
					// _, err := tpm2.PolicyCommandCode{
					// 	PolicySession: handle,
					// 	Code:          tpm2.TPMCCDuplicate,
					// }.Execute(tpm)

					_, err = tpm2.PolicyDuplicationSelect{
						PolicySession: handle,
						NewParentName: rsp.Name,
						ObjectName:    createLoadedResp.Name,
					}.Execute(rwr)

					if err != nil {
						return err
					}
					return nil
				})),
			},
			NewParentHandle: tpm2.NamedHandle{
				Handle: rsp.ObjectHandle,
				Name:   rsp.Name,
			},
			Symmetric: tpm2.TPMTSymDef{
				Algorithm: tpm2.TPMAlgNull,
			},
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("duplicateResp can't crate duplicate %v", err)
		}

		// generate the duplication data
		dupPub = createLoadedResp.OutPublic.Bytes()
		dupSeed = duplicateResp.OutSymSeed.Buffer
		dupDup = duplicateResp.Duplicate.Buffer

		// now use the inner AES key and the userAuth policy we set on the TPM-based AES key
		//  to encrypt the provided key by the go-wrapping library (i.,e use the TPM key to encrypt (env.Key) which is the DEK)
		keyAuth2 := tpm2.AuthHandle{
			Handle: createLoadedResp.ObjectHandle,
			Name:   createLoadedResp.Name,
			Auth:   tpm2.PasswordAuth([]byte(s.userAuth)),
		}
		kek, err = encryptDecryptSymmetric(rwr, keyAuth2, iv, env.Key, rsessInOut, false)
		if err != nil {
			return nil, fmt.Errorf("EncryptSymmetric failed: %s", err)
		}

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
		Type:     tpmwrappb.Secret_DUPLICATE,
		Pcrs:     pr,
		UserAuth: hasUserAuth,
		Key: &tpmwrappb.Secret_DuplicatedOp{
			&tpmwrappb.DuplicatedKey{
				Name:    s.keyName,
				Kek:     kek,
				EkPub:   []byte(s.encryptingPublicKey),
				Iv:      iv,
				DupPub:  dupPub,
				DupDup:  dupDup,
				DupSeed: dupSeed,
			},
		},
	}

	b, err := protojson.Marshal(wrappb)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap proto Key: %v", err)
	}

	if err != nil {
		return nil, fmt.Errorf("marshaling error: %v", err)
	}

	// Store current key id value
	s.currentKeyId.Store(s.keyName)

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
			KeyId:      s.keyName,
			WrappedKey: b,
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
		rwc, err = openTPM(s.tpmPath)
		if err != nil {
			return nil, fmt.Errorf("can't open TPM %q: %v", s.tpmPath, err)
		}
		defer rwc.Close()
	}
	rwr := transport.FromReadWriter(rwc)

	// first setup session encryption with the EK
	rsessIn := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn))

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsessIn.Handle(),
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	encsess := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut))
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: encsess.Handle(),
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	createEKRsp, err := tpm2.CreatePrimary{
		//PrimaryHandle: tpm2.TPMRHEndorsement,
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth([]byte(s.hierarchyAuth)),
		},
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
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
	rsessIn = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub))

	// Default to mechanism used before key info was stored
	if in.KeyInfo == nil {
		in.KeyInfo = &wrapping.KeyInfo{
			Mechanism: TPMImport,
		}
	}

	wrappb := &tpmwrappb.Secret{}
	err = protojson.Unmarshal(in.KeyInfo.WrappedKey, wrappb)
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

	if wrappb.Type != tpmwrappb.Secret_DUPLICATE {
		return nil, fmt.Errorf("incorrect keytype, expected Secret_DUPLICATE")
	}

	pbk, ok := wrappb.GetKey().(*tpmwrappb.Secret_DuplicatedOp)
	if !ok {
		return nil, fmt.Errorf("error unmarshalling tpmwrappb.Secret_DuplicatedOp")
	}

	if s.encryptingPublicKey != "" {

		ekPubDup, err := hex.DecodeString(string(pbk.DuplicatedOp.EkPub))
		if err != nil {
			return nil, fmt.Errorf(" error decoding encoded ekPub: %v", err)
		}

		blockK, _ := pem.Decode(ekPubDup)

		parsedK, err := x509.ParsePKIXPublicKey(blockK.Bytes)
		if err != nil {
			return nil, fmt.Errorf(" unable parsing encrypting public key from blob : %v", err)
		}

		rsaPubK, ok := parsedK.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf(" error converting encryptingPublicKey encrypting public key from blob")
		}

		ekPubParam, err := hex.DecodeString(string(s.encryptingPublicKey))
		if err != nil {
			return nil, fmt.Errorf(" error decoding encoded ekPub: %v", err)
		}

		blockP, _ := pem.Decode(ekPubParam)
		parsedP, err := x509.ParsePKIXPublicKey(blockP.Bytes)
		if err != nil {
			return nil, fmt.Errorf(" unable parsing encrypting public key from parameter : %v", err)
		}

		rsaPubP, ok := parsedP.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf(" error converting  public key from blob")
		}

		if !rsaPubK.Equal(rsaPubP) {
			return nil, fmt.Errorf("provided encrypting public key does not match what the key is encoded against expected \n%s\n got \n%s\n", string(ekPubDup), string(ekPubParam))
		}
	}

	if s.userAuth != "" && len(wrappb.Pcrs) > 0 {
		return nil, fmt.Errorf("both userAuth and PCR policies currently not supported.  Set either userAuth or pcrs")
	}

	if s.debug {
		fmt.Printf("Key PolicyType %s\n", wrappb.Type)
	}

	dupPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](pbk.DuplicatedOp.DupPub)
	if err != nil {
		return nil, fmt.Errorf(" unmarshal public  %v", err)
	}

	var plaintext []byte
	switch in.KeyInfo.Mechanism {
	case TPMImport:

		// create the EK (this is the default parent key we exported to the remote TPM)
		cPrimary, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
				Auth:   tpm2.PasswordAuth([]byte(s.hierarchyAuth)),
			},
			InPublic: tpm2.New2B(tpm2.RSAEKTemplate), // tpm2.New2B(ECCSRKHTemplate),
		}.Execute(rwr, rsessIn)
		if err != nil {
			return nil, fmt.Errorf("can't create primary TPM %v", err)
		}
		defer func() {
			flush := tpm2.FlushContext{
				FlushHandle: cPrimary.ObjectHandle,
			}
			_, _ = flush.Execute(rwr)
		}()

		// first create a session on the TPM which will allow use of the EK.
		//  using EK here needs PolicySecret
		import_sess, import_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer import_session_cleanup()

		_, err = tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
				Auth:   tpm2.PasswordAuth([]byte(s.hierarchyAuth)),
			},
			PolicySession: import_sess.Handle(),
			NonceTPM:      import_sess.NonceTPM(),
		}.Execute(rwr, rsessIn)
		if err != nil {
			return nil, fmt.Errorf("error setting policy PolicyDuplicationSelect %v", err)
		}

		importResp, err := tpm2.Import{
			ParentHandle: tpm2.AuthHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
				Auth:   import_sess,
			},
			ObjectPublic: tpm2.New2B(*dupPub),
			Duplicate: tpm2.TPM2BPrivate{
				Buffer: pbk.DuplicatedOp.DupDup,
			},
			InSymSeed: tpm2.TPM2BEncryptedSecret{
				Buffer: pbk.DuplicatedOp.DupSeed,
			},
		}.Execute(rwr, rsessIn)
		if err != nil {
			return nil, fmt.Errorf("can't run import dup %v", err)
		}

		err = import_session_cleanup()
		if err != nil {
			return nil, fmt.Errorf("can't run flush session %v", err)
		}

		load_session, load_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, fmt.Errorf("setting up trial session: %v", err)
		}
		defer load_session_cleanup()

		_, err = tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
				Auth:   tpm2.PasswordAuth([]byte(s.hierarchyAuth)),
			},
			PolicySession: load_session.Handle(),
			NonceTPM:      load_session.NonceTPM(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error setting policy PolicySecret %v", err)
		}

		loadkRsp, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
				Auth:   load_session,
			},
			InPrivate: importResp.OutPrivate,
			InPublic:  tpm2.New2B(*dupPub),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("can't load object %v", err)
		}

		defer func() {
			flush := tpm2.FlushContext{
				FlushHandle: loadkRsp.ObjectHandle,
			}
			_, _ = flush.Execute(rwr)
		}()

		var decrypted []byte

		// check if pcrValues are set or if we should use userAuth (not both)
		if len(pcrList) > 0 {

			sel := tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
					},
				},
			}

			// create a real policy session for the PCR values

			pcr_sess, pcr_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				return nil, fmt.Errorf("setting up trial session: %v", err)
			}
			defer pcr_cleanup()

			_, err = tpm2.PolicyPCR{
				PolicySession: pcr_sess.Handle(),
				Pcrs: tpm2.TPMLPCRSelection{
					PCRSelections: sel.PCRSelections,
				},
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("error executing PolicyPCR: %v", err)
			}

			// get its digest
			pcrpgd, err := tpm2.PolicyGetDigest{
				PolicySession: pcr_sess.Handle(),
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("error executing PolicyGetDigest: %v", err)
			}
			err = pcr_cleanup()
			if err != nil {
				return nil, fmt.Errorf("error purging session: %v", err)
			}

			// create another real session with the PolicyDuplicationSelect and remember to specify the EK
			// as the "new parent"
			dupselect_sess, dupselect_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				return nil, fmt.Errorf("setting up trial session: %v", err)
			}
			defer dupselect_cleanup()

			_, err = tpm2.PolicyDuplicationSelect{
				PolicySession: dupselect_sess.Handle(),
				NewParentName: cPrimary.Name,
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("error setting policy duplicationSelect %v", err)
			}

			// calculate the digest
			dupselpgd, err := tpm2.PolicyGetDigest{
				PolicySession: dupselect_sess.Handle(),
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("error executing PolicyGetDigest: %v", err)
			}
			err = dupselect_cleanup()
			if err != nil {
				return nil, fmt.Errorf("error purging session: %v", err)
			}

			// now create an OR session with the two above policies above

			or_sess, or_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				return nil, fmt.Errorf("setting up trial session: %v", err)
			}
			defer or_cleanup()

			_, err = tpm2.PolicyPCR{
				PolicySession: or_sess.Handle(),
				Pcrs: tpm2.TPMLPCRSelection{
					PCRSelections: sel.PCRSelections,
				},
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("error executing PolicyPCR: %v", err)
			}

			_, err = tpm2.PolicyOr{
				PolicySession: or_sess.Handle(),
				PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd.PolicyDigest}},
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("aaa error setting policyOR %v", err)
			}

			// we now have a session which'll allow us to decrypt the DEK
			keyAuth2 := tpm2.AuthHandle{
				Handle: loadkRsp.ObjectHandle,
				Name:   loadkRsp.Name,
				Auth:   or_sess,
			}

			decrypted, err = encryptDecryptSymmetric(rwr, keyAuth2, pbk.DuplicatedOp.Iv, pbk.DuplicatedOp.Kek, rsessIn, true)
			if err != nil {
				return nil, fmt.Errorf("EncryptSymmetric failed: %s", err)
			}

		} else {

			// flush parent (we dont' need it here)
			flush := tpm2.FlushContext{FlushHandle: cPrimary.ObjectHandle}
			_, err = flush.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("can't close TPM %v", err)
			}

			// setup an auth handle for the duplicated key and specify the userAuth (password)
			keyAuth2 := tpm2.AuthHandle{
				Handle: loadkRsp.ObjectHandle,
				Name:   loadkRsp.Name,
				Auth:   tpm2.PasswordAuth([]byte(s.userAuth)),
			}

			// decrypt the DEK
			decrypted, err = encryptDecryptSymmetric(rwr, keyAuth2, pbk.DuplicatedOp.Iv, pbk.DuplicatedOp.Kek, rsessIn, true)
			if err != nil {
				return nil, fmt.Errorf("EncryptSymmetric failed: %s", err)
			}
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

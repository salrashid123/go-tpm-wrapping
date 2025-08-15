package tpmwrap

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"sync/atomic"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrappb "github.com/salrashid123/go-tpm-wrapping/tpmwrappb"
	genkeyutil "github.com/salrashid123/tpm2genkey/util"

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

	// first encrypt the provided plaintext using the underlying library
	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	// currently both userauth and pcr policy are not supported together
	if s.userAuth != "" && s.pcrValues != "" {
		return nil, fmt.Errorf("both userAuth and PCR policies currently not supported.  Set either userAuth or pcrs")
	}

	// first read the remote TPM-A's encryption public key and attempt to derive its "name"
	if s.encryptingPublicKey == "" {
		return nil, fmt.Errorf("encrypting public key must be set")
	}

	pubPEMData, err := hex.DecodeString(s.encryptingPublicKey)
	if err != nil {
		return nil, fmt.Errorf(" error decoding public key  : %v", err)
	}

	var ekPububFromPEMTemplate tpm2.TPMTPublic

	var parentKeyType tpmwrappb.DuplicatedKey_ParentKeyType
	block, _ := pem.Decode(pubPEMData)
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(" unable parsing encrypting public key : %v", err)
	}

	switch pub := parsedKey.(type) {
	case *rsa.PublicKey:
		rsaPub, ok := parsedKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf(" error converting encryptingPublicKey to rsa")
		}
		parentKeyType = tpmwrappb.DuplicatedKey_EndorsementRSA
		ekPububFromPEMTemplate = tpm2.RSAEKTemplate
		ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: rsaPub.N.Bytes(),
			},
		)
	case *ecdsa.PublicKey:
		ecPub, ok := parsedKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf(" error converting encryptingPublicKey to ecdsa")
		}
		parentKeyType = tpmwrappb.DuplicatedKey_EndorsementtECC
		ekPububFromPEMTemplate = tpm2.ECCEKTemplate
		ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: ecPub.X.Bytes(),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: ecPub.Y.Bytes(),
				},
			},
		)
	default:
		return nil, fmt.Errorf("unsupported public key type %v", pub)
	}

	ekName, err := tpm2.ObjectName(&ekPububFromPEMTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to get name key: %v", err)
	}

	if s.debug {
		fmt.Printf("EK Name %s\n", hex.EncodeToString(ekName.Buffer))
	}

	/// ************************************8

	var dupPub []byte
	var dupDup []byte
	var dupSeed []byte
	var ap []*keyfile.TPMPolicy
	var finalPolicyDigest []byte

	var ekrsaPub *rsa.PublicKey
	var ekeccPub *ecdsa.PublicKey
	var aeskeybits *tpm2.TPMKeyBits

	if parentKeyType == tpmwrappb.DuplicatedKey_EndorsementRSA {
		rsaDetailB, err := ekPububFromPEMTemplate.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf(" error getting RSADetail %v ", err)
		}

		rsaUniqueB, err := ekPububFromPEMTemplate.Unique.RSA()
		if err != nil {
			return nil, fmt.Errorf(" error getting RSA Unique %v ", err)

		}

		ekrsaPub, err = tpm2.RSAPub(rsaDetailB, rsaUniqueB)
		if err != nil {
			return nil, fmt.Errorf(" error getting RSA Publcic key from template %v ", err)
		}

		aeskeybits, err = rsaDetailB.Symmetric.KeyBits.AES()
		if err != nil {
			return nil, fmt.Errorf("error getting AESKeybits: %v", err)
		}

	} else {
		ecDetail, err := ekPububFromPEMTemplate.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("error getting ECCDetail %v ", err)
		}

		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return nil, fmt.Errorf(" error getting ECC Curve %v ", err)
		}
		eccUnique, err := ekPububFromPEMTemplate.Unique.ECC()
		if err != nil {
			return nil, fmt.Errorf("error getting ECC Public Key from template %v ", err)
		}

		ekeccPub = &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
		aeskeybits, err = ecDetail.Symmetric.KeyBits.AES()
		if err != nil {
			return nil, fmt.Errorf("error getting AESKeybits: %v", err)
		}

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
		if s.debug {
			fmt.Printf("PCR Hash: %s\n", hex.EncodeToString(pcrHash))
		}
		papcr := tpm2.PolicyPCR{
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: pcrHash,
			},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
		}

		pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("error setting up NewPolicyCalculator for PolicyAuthValue : %v", err)
		}
		err = papcr.Update(pol)
		if err != nil {
			return nil, fmt.Errorf("error updating NewPolicyCalculator for PolicyAuthValue %v", err)
		}
		e, err := genkeyutil.CPBytes(papcr)
		if err != nil {
			return nil, fmt.Errorf("error creating cpbytes PolicyAuthValue: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyPCR),
			CommandPolicy: e,
		})

		// create a trial session with PolicyDuplicationSelect which stipulates the target systems
		// where this key can get duplicated

		pds := tpm2.PolicyDuplicationSelect{
			NewParentName: *ekName,
		}

		polds, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("error setting up NewPolicyCalculator for policyDuplicateSelect: %v", err)
		}
		err = pds.Update(polds)
		if err != nil {
			return nil, fmt.Errorf("error updating NewPolicyCalculator for policyDuplicateSelect: %v", err)
		}
		de, err := genkeyutil.CPBytes(pds)
		if err != nil {
			return nil, fmt.Errorf("error creating cpbytes PolicyDuplicationSelect: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyDuplicationSelect),
			CommandPolicy: de,
		})

		por := tpm2.PolicyOr{
			PHashList: tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{{Buffer: pol.Hash().Digest}, {Buffer: polds.Hash().Digest}}},
		}

		polOR, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("error setting up NewPolicyCalculator for policyOR: %v", err)
		}
		err = por.Update(polOR)
		if err != nil {
			return nil, fmt.Errorf("error updating NewPolicyCalculator for policyOR: %v", err)
		}

		porA, err := genkeyutil.CPBytes(por)
		if err != nil {
			return nil, fmt.Errorf("error creating cpbytes PolicyOr: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyOR),
			CommandPolicy: porA,
		})

		finalPolicyDigest = polOR.Hash().Digest

	} else {
		paa := tpm2.PolicyAuthValue{}

		pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("error setting up NewPolicyCalculator for PolicyAuthValue : %v", err)
		}
		err = paa.Update(pol)
		if err != nil {
			return nil, fmt.Errorf("error updating NewPolicyCalculator for PolicyAuthValue %v", err)
		}
		e, err := genkeyutil.CPBytes(paa)
		if err != nil {
			return nil, fmt.Errorf("error creating cpbytes PolicyAuthValue: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyAuthValue),
			CommandPolicy: e,
		})

		pds := tpm2.PolicyDuplicationSelect{
			NewParentName: *ekName,
		}

		polds, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("error setting up NewPolicyCalculator for policyDuplicateSelect: %v", err)
		}
		err = pds.Update(polds)
		if err != nil {
			return nil, fmt.Errorf("error updating NewPolicyCalculator for policyDuplicateSelect: %v", err)
		}
		de, err := genkeyutil.CPBytes(pds)
		if err != nil {
			return nil, fmt.Errorf("error creating cpbytes PolicyDuplicationSelect: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyDuplicationSelect),
			CommandPolicy: de,
		})

		por := tpm2.PolicyOr{
			PHashList: tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{{Buffer: pol.Hash().Digest}, {Buffer: polds.Hash().Digest}}},
		}

		polOR, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("error setting up NewPolicyCalculator for policyOR: %v", err)
		}
		err = por.Update(polOR)
		if err != nil {
			return nil, fmt.Errorf("error updating NewPolicyCalculator for policyOR: %v", err)
		}

		porA, err := genkeyutil.CPBytes(por)
		if err != nil {
			return nil, fmt.Errorf("error creating cpbytes PolicyOr: %v", err)
		}

		ap = append(ap, &keyfile.TPMPolicy{
			CommandCode:   int(tpm2.TPMCCPolicyOR),
			CommandPolicy: porA,
		})

		finalPolicyDigest = polOR.Hash().Digest

	}

	keySensitive := env.Key

	sv := make([]byte, 32)
	io.ReadFull(rand.Reader, sv)
	privHash := crypto.SHA256.New()
	privHash.Write(sv)
	privHash.Write(keySensitive)

	dupTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: finalPolicyDigest,
		},
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BDigest{
				Buffer: privHash.Sum(nil),
			},
		),
	}

	dupSensitive := tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue: tpm2.TPM2BDigest{
			Buffer: sv,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BSensitiveData{Buffer: keySensitive},
		),
		AuthValue: tpm2.TPM2BAuth{
			Buffer: []byte(s.userAuth),
		},
	}

	sens := dupSensitive
	sens2B := tpm2.Marshal(sens)

	packedSecret := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	var seed, encryptedSeed []byte

	h, err := ekPububFromPEMTemplate.NameAlg.Hash()
	if err != nil {
		return nil, fmt.Errorf("error getting nameHash from EKTemplate %v", err)
	}

	switch parentKeyType {
	case tpmwrappb.DuplicatedKey_EndorsementRSA:
		//  start createRSASeed
		seedSize := *aeskeybits / 8
		seed = make([]byte, seedSize)
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return nil, fmt.Errorf("error getting random for EKRSA %v ", err)
		}

		es, err := rsa.EncryptOAEP(
			h.New(),
			rand.Reader,
			ekrsaPub,
			seed,
			[]byte("DUPLICATE\x00"))
		if err != nil {
			return nil, fmt.Errorf("error  EncryptOAEP: %v", err)
		}

		encryptedSeed, err = tpmutil.Pack(es)
		if err != nil {
			return nil, fmt.Errorf("error packing encryptedseed: %v", err)
		}

	case tpmwrappb.DuplicatedKey_EndorsementtECC, tpmwrappb.DuplicatedKey_H2:

		ecp, err := ecdsa.GenerateKey(ekeccPub.Curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ecc key %v ", err)
		}
		x := ecp.X
		y := ecp.Y
		priv := ecp.D.Bytes()
		z, _ := ekeccPub.Curve.ScalarMult(ekeccPub.X, ekeccPub.Y, priv)

		create, err := ekPububFromPEMTemplate.NameAlg.Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to get hash from template %v ", err)
		}
		xBytes := eccIntToBytes(ekeccPub.Curve, x)
		seed = tpm2.KDFe(
			h,
			eccIntToBytes(ekeccPub.Curve, z),
			"DUPLICATE",
			xBytes,
			eccIntToBytes(ekeccPub.Curve, ekeccPub.X),
			create.Size()*8)
		if err != nil {
			return nil, fmt.Errorf("failed to create kdfe: %v", err)
		}

		encryptedSeed, err = tpmutil.Pack(tpmutil.U16Bytes(xBytes), tpmutil.U16Bytes(eccIntToBytes(ekeccPub.Curve, y)))
		if err != nil {
			return nil, fmt.Errorf("failed  to pack  encryptedseed: %v", err)
		}
	default:
		return nil, fmt.Errorf("failed  to pack  encryptedseed: %v", err)
	}

	name, err := tpm2.ObjectName(&dupTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to get name key: %v", err)
	}

	nameEncoded := name.Buffer

	symSize := int(*aeskeybits)

	h2, err := ekPububFromPEMTemplate.NameAlg.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to get ek.Scheme.Scheme.Hash: %v", err)
	}

	symmetricKey := tpm2.KDFa(
		h2,
		seed,
		"STORAGE",
		nameEncoded,
		/*contextV=*/ nil,
		symSize)
	if err != nil {
		return nil, fmt.Errorf("failed to kdfa: %v", err)
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get aes cipher: %v", err)
	}
	encryptedSecret := make([]byte, len(packedSecret))
	iv := make([]byte, len(symmetricKey))
	cipher.NewCFBEncrypter(c, iv).XORKeyStream(encryptedSecret, packedSecret)
	// end encryptSecret

	// start createHMAC
	h3, err := ekPububFromPEMTemplate.NameAlg.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed ek.Scheme.Scheme.Hash: %v", err)
	}

	macKey := tpm2.KDFa(
		h3,
		seed,
		"INTEGRITY",
		/*contextU=*/ nil,
		/*contextV=*/ nil,
		h3.New().Size()*8)

	mac := hmac.New(func() hash.Hash { return h.New() }, macKey)
	mac.Write(encryptedSecret)
	mac.Write(nameEncoded)
	hmacSum := mac.Sum(nil)
	// end createHMAC

	dup := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: hmacSum})
	dup = append(dup, encryptedSecret...)

	pubEncoded := tpm2.Marshal(&dupTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to get name key: %v", err)
	}
	dupPub = pubEncoded
	dupDup = dup
	dupSeed = encryptedSeed

	// create the protobuf and include specifications of the duplicated key we just used
	var pr []*tpmwrappb.PCRS
	for i, k := range pcrMap {
		pr = append(pr, &tpmwrappb.PCRS{
			Pcr:   int32(i),
			Value: k,
		})
	}

	tkey := keyfile.TPMKey{
		Keytype:   keyfile.OIDImportableKey,
		EmptyAuth: true,
		Parent:    tpm2.TPMRHFWOwner,
		Policy:    ap,
		Secret:    tpm2.TPM2BEncryptedSecret{Buffer: dupSeed},
		Privkey:   tpm2.TPM2BPrivate{Buffer: dupDup},
		Pubkey:    tpm2.BytesAs2B[tpm2.TPMTPublic](dupPub),
	}

	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, &tkey)
	if err != nil {
		return nil, fmt.Errorf("error encoding keyfile %v", err)
	}

	wrappb := &tpmwrappb.Secret{
		Name:    s.keyName,
		Version: KEY_VERSION,
		Type:    tpmwrappb.Secret_DUPLICATE,
		Pcrs:    pr,

		Key: &tpmwrappb.Secret_DuplicatedOp{
			&tpmwrappb.DuplicatedKey{
				Name:       s.keyName,
				EKPub:      []byte(s.encryptingPublicKey),
				ParentName: hex.EncodeToString(ekName.Buffer),
				Keyfile:    string(keyFileBytes.Bytes()),
			},
		},
	}

	// get the bytes of the protobuf
	b, err := protojson.Marshal(wrappb)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap proto Key: %v", err)
	}

	// Store current key id value
	s.currentKeyId.Store(s.keyName)

	// return the cipher, the original IV we used in  wrapping.EnvelopeEncrypt(plaintext, opt...)
	// and the bytes of the protobuf as the wrapped key
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

	// greate a basic encryption session
	encsess := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut))
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: encsess.Handle(),
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// get the primary ek which we use for subsequent encryption sessions
	createEKRsp, err := tpm2.CreatePrimary{
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

	// compare the sesion "name" we just got with the values the user provided
	if s.encryptedSessionName != "" {
		if s.encryptedSessionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			return nil, fmt.Errorf("session encryption names do not match expected [%s] got [%s]", s.encryptedSessionName, hex.EncodeToString(createEKRsp.Name.Buffer))
		}
	}

	encryptionPub, err := createEKRsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("error getting session encryption public contents %v", err)
	}

	// create an actual full encryption session using the EK we trust
	rsessInOut := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *encryptionPub))
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsessInOut.Handle(),
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// Default to mechanism used before key info was stored
	if in.KeyInfo == nil {
		in.KeyInfo = &wrapping.KeyInfo{
			Mechanism: TPMImport,
		}
	}

	// decode the protobuf
	wrappb := &tpmwrappb.Secret{}
	err = protojson.Unmarshal(in.KeyInfo.WrappedKey, wrappb)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap proto Key: %v", err)
	}

	if wrappb.Version != KEY_VERSION {
		return nil, fmt.Errorf("key is encoded by key version [%d] which is incompatile with the current version [%d]", wrappb.Version, KEY_VERSION)
	}

	if s.debug {
		fmt.Printf("Decrypting with name %s\n", wrappb.Name)
	}

	if wrappb.Type != tpmwrappb.Secret_DUPLICATE {
		return nil, fmt.Errorf("incorrect keytype, expected Secret_DUPLICATE")
	}

	pbk, ok := wrappb.GetKey().(*tpmwrappb.Secret_DuplicatedOp)
	if !ok {
		return nil, fmt.Errorf("error unmarshalling tpmwrappb.Secret_DuplicatedOp")
	}

	// if the encoded protobuf saved the PEM key we used to do the duplicate, comapre
	// that with the current EK we just got.  This step isn't necessary since we
	// wont' be able to decrypt anyway

	var pubAlg tpm2.TPM2BPublic

	if s.encryptingPublicKey != "" {

		ekPubDup, err := hex.DecodeString(string(pbk.DuplicatedOp.EKPub))
		if err != nil {
			return nil, fmt.Errorf(" error decoding encoded ekPub: %v", err)
		}

		blockK, _ := pem.Decode(ekPubDup)

		parsedK, err := x509.ParsePKIXPublicKey(blockK.Bytes)
		if err != nil {
			return nil, fmt.Errorf(" unable parsing encrypting public key from blob : %v", err)
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

		switch pub := parsedP.(type) {
		case *rsa.PublicKey:
			rsaPubPK, ok := parsedK.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf(" error converting encryptingPublicKey to rsa")
			}
			rsaPubP, ok := parsedP.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf(" error converting encryptingPublicKey to rsa")
			}
			if !rsaPubP.Equal(rsaPubPK) {
				return nil, fmt.Errorf("provided encrypting public key does not match what the key is encoded against expected \n%s\n got \n%s", string(ekPubDup), string(ekPubParam))
			}
			pubAlg = tpm2.New2B(tpm2.RSAEKTemplate)
		case *ecdsa.PublicKey:
			ecPubPK, ok := parsedK.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf(" error converting encryptingPublicKey to ec")
			}
			ecPubP, ok := parsedP.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf(" error converting encryptingPublicKey to ec")
			}
			if !ecPubP.Equal(ecPubPK) {
				return nil, fmt.Errorf("provided encrypting public key does not match what the key is encoded against expected \n%s\n got \n%s", string(ekPubDup), string(ekPubParam))
			}
			pubAlg = tpm2.New2B(tpm2.ECCEKTemplate)
		default:
			return nil, fmt.Errorf("unsupported public key type %v", pub)
		}
	}

	if s.userAuth != "" && len(wrappb.Pcrs) > 0 {
		return nil, fmt.Errorf("both userAuth and PCR policies currently not supported.  Set either userAuth or pcrs")
	}

	if s.debug {
		fmt.Printf("Key PolicyType %s\n", wrappb.Type)
	}

	kf, err := keyfile.Decode([]byte(pbk.DuplicatedOp.Keyfile))
	if err != nil {
		return nil, fmt.Errorf(" unmarshal secret.key %v", err)
	}

	// extract the duplicated keys into structures we can use
	dupPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](kf.Pubkey.Bytes())
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
			InPublic: pubAlg,
		}.Execute(rwr, rsessInOut)
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
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("error setting policy PolicyDuplicationSelect %v", err)
		}

		// now import the duplicated key
		importResp, err := tpm2.Import{
			ParentHandle: tpm2.AuthHandle{
				Handle: cPrimary.ObjectHandle,
				Name:   cPrimary.Name,
				Auth:   import_sess,
			},
			ObjectPublic: kf.Pubkey, //tpm2.New2B(*dupPub),
			Duplicate: tpm2.TPM2BPrivate{
				Buffer: kf.Privkey.Buffer,
			},
			InSymSeed: tpm2.TPM2BEncryptedSecret{
				Buffer: kf.Secret.Buffer,
			},
		}.Execute(rwr, rsessInOut)
		if err != nil {
			return nil, fmt.Errorf("can't run import dup %v", err)
		}

		err = import_session_cleanup()
		if err != nil {
			return nil, fmt.Errorf("can't run flush session %v", err)
		}

		// create a new session to load
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

		var decrypted []byte
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

			flush := tpm2.FlushContext{FlushHandle: cPrimary.ObjectHandle}
			_, err = flush.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("can't close TPM %v", err)
			}

			tc, err := NewPCRAndDuplicateSelectSession(rwr, sel.PCRSelections, tpm2.TPM2BDigest{Buffer: pcrDigest}, []byte(s.userAuth), cPrimary.Name)
			if err != nil {
				return nil, fmt.Errorf("error creating NewPCRAndDuplicateSelectSession%v", err)
			}

			or_sess, or_cleanup, err := tc.GetSession()
			if err != nil {
				return nil, fmt.Errorf("error getting session: %v", err)
			}
			defer or_cleanup()
			// now unseal the sensitive bit (this was the original env.Key value set during encryption)
			unseaResp, err := tpm2.Unseal{
				ItemHandle: tpm2.AuthHandle{
					Handle: loadkRsp.ObjectHandle,
					Name:   loadkRsp.Name,
					Auth:   or_sess,
				},
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("unseal failed: %s", err)
			}

			decrypted = unseaResp.OutData.Buffer

		} else {

			// flush parent (we dont' need it here)
			flush := tpm2.FlushContext{FlushHandle: cPrimary.ObjectHandle}
			_, err = flush.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("can't close TPM %v", err)
			}

			tc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(s.userAuth), cPrimary.Name)
			if err != nil {
				return nil, fmt.Errorf("error creating NewPolicyAuthValueAndDuplicateSelectSession%v", err)
			}

			or_sess, or_cleanup, err := tc.GetSession()
			if err != nil {
				return nil, fmt.Errorf("error getting session: %v", err)
			}
			defer or_cleanup()

			unseaResp, err := tpm2.Unseal{
				ItemHandle: tpm2.AuthHandle{
					Handle: loadkRsp.ObjectHandle,
					Name:   loadkRsp.Name,
					Auth:   or_sess,
				},
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("unseal failed: %s", err)
			}

			decrypted = unseaResp.OutData.Buffer
		}

		// set the original encryption key, the iv and ciphertext as the struct
		envInfo := &wrapping.EnvelopeInfo{
			Key:        decrypted,
			Iv:         in.Iv,
			Ciphertext: in.Ciphertext,
		}

		// reverse the whole operation
		plaintext, err = wrapping.EnvelopeDecrypt(envInfo, opt...)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data with envelope: %w", err)
		}

	default:
		return nil, fmt.Errorf("invalid mechanism: %d", in.KeyInfo.Mechanism)
	}

	return plaintext, nil
}

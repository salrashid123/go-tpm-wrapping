package tpmwrap

import (
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"

	//"github.com/google/go-tpm/tpm2"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	EnvTPMPath             = "TPM_PATH"
	EnvPCRValues           = "TPM_PCR_VALUES"
	EnvEncryptingPublicKey = "TPM_ENCRYPTING_PUBLIC_KEY"
	EnvUserAuth            = "TPM_USER_AUTH"
	EnvHierarchyAuth       = "TPM_HIERARCHY_AUTH"
	EnvParentKeyH2         = "TPM_PARENT_KEY_H2"

	EnvKeyName               = "TPM_KEY_NAME"
	EnvDEBUG                 = "TPM_DEBUG"
	EnvSessionEncryptionName = "TPM_SESSION_ENCRYPTION_NAME"

	TPM_PATH                = "tpm_path"
	PCR_VALUES              = "pcr_values"
	USER_AUTH               = "user_auth"
	HIERARCHY_AUTH          = "hierarchy_auth"
	KEY_NAME                = "key_name"
	PARENT_KEY_H2           = "parent_key_h2"
	ENCRYPTING_PUBLIC_KEY   = "encrypting_public_key"
	SESSION_ENCRYPTION_NAME = "session_encryption_name"

	KEY_VERSION = 2

	DEBUG = "debug"
)

const (
	TPMSeal = iota
	TPMImport
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}

var ()

func getPCRMap(algo tpm2.TPMAlgID, expectedPCRMap string) (map[uint][]byte, []uint, []byte, error) {

	pcrMap := make(map[uint][]byte)

	if expectedPCRMap == "" {
		return pcrMap, nil, nil, nil
	}
	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm2.TPMAlgSHA1 {
		hsh = sha1.New()
	}
	if algo == tpm2.TPMAlgSHA256 {
		hsh = sha256.New()
	}
	if algo == tpm2.TPMAlgSHA1 || algo == tpm2.TPMAlgSHA256 {
		for _, v := range strings.Split(expectedPCRMap, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return nil, nil, nil, fmt.Errorf(" PCR key:value is invalid in parsing %s", v)
				}
				hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
				if err != nil {
					return nil, nil, nil, fmt.Errorf(" PCR key:value is invalid in encoding %s", v)
				}
				pcrMap[uint(uv)] = hexEncodedPCR
				hsh.Write(hexEncodedPCR)
			} else {
				return nil, nil, nil, fmt.Errorf(" PCR key:value is invalid %s", v)
			}
		}
	} else {
		return nil, nil, nil, fmt.Errorf("unknown Hash Algorithm for TPM PCRs %v", algo)
	}
	// if len(pcrMap) == 0 {
	// 	return nil, nil, nil, fmt.Errorf(" PCRMap is null")
	// }

	pcrs := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		pcrs = append(pcrs, k)
	}

	return pcrMap, pcrs, hsh.Sum(nil), nil
}

func eccIntToBytes(curve elliptic.Curve, i *big.Int) []byte {
	bytes := i.Bytes()
	curveBytes := (curve.Params().BitSize + 7) / 8
	return append(make([]byte, curveBytes-len(bytes)), bytes...)
}

type PolicyAuthValueDuplicateSelectSession struct {
	rwr      transport.TPM
	password []byte
	ekName   tpm2.TPM2BName
}

func NewPolicyAuthValueAndDuplicateSelectSession(rwr transport.TPM, password []byte, ekName tpm2.TPM2BName) (PolicyAuthValueDuplicateSelectSession, error) {
	return PolicyAuthValueDuplicateSelectSession{rwr, password, ekName}, nil
}

func (p PolicyAuthValueDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	pa_sess, pa_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	//defer pa_cleanup()

	_, err = tpm2.PolicyAuthValue{
		PolicySession: pa_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	papgd, err := tpm2.PolicyGetDigest{
		PolicySession: pa_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = pa_cleanup()
	if err != nil {
		return nil, nil, err
	}
	// as the "new parent"
	dupselect_sess, dupselect_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	//defer dupselect_cleanup()

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: tpm2.TPM2BName(p.ekName),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}
	// now create an OR session with the two above policies above
	or_sess, or_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password))}...)
	if err != nil {
		return nil, nil, err
	}
	//defer or_cleanup()

	_, err = tpm2.PolicyAuthValue{
		PolicySession: or_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{papgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	return or_sess, or_cleanup, nil
}

type PCRAndDuplicateSelectSession struct {
	rwr      transport.TPM
	sel      []tpm2.TPMSPCRSelection
	digest   tpm2.TPM2BDigest
	password []byte
	ekName   tpm2.TPM2BName
}

func NewPCRAndDuplicateSelectSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, digest tpm2.TPM2BDigest, password []byte, ekName tpm2.TPM2BName) (PCRAndDuplicateSelectSession, error) {
	return PCRAndDuplicateSelectSession{rwr, sel, digest, password, ekName}, nil
}

func (p PCRAndDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	pcr_sess, pcr_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: pcr_sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, pcr_cleanup, err
	}

	pcrpgd, err := tpm2.PolicyGetDigest{
		PolicySession: pcr_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, pcr_cleanup, err
	}
	err = pcr_cleanup()
	if err != nil {
		return nil, nil, err
	}

	// create another real session with the PolicyDuplicationSelect and remember to specify the EK
	// as the "new parent"
	dupselect_sess, dupselect_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: p.ekName,
	}.Execute(p.rwr)
	if err != nil {
		return nil, dupselect_cleanup, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, dupselect_cleanup, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}

	// now create an OR session with the two policies above
	or_sess, or_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	//defer or_cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: or_sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, or_cleanup, err
	}

	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, or_cleanup, err
	}

	return or_sess, or_cleanup, nil
}

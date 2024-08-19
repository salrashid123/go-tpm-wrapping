package tpmwrap

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
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
	EnvKeyName             = "TPM_KEY_NAME"
	EnvDEBUG               = "TPM_DEBUG"
	// EnvSessionEncryptionName = "TPM_SESSION_ENCRYPTION_NAME"

	TPM_PATH              = "tpm_path"
	PCR_VALUES            = "pcr_values"
	USER_AUTH             = "user_auth"
	HIERARCHY_AUTH        = "hierarchy_auth"
	KEY_NAME              = "key_name"
	ENCRYPTING_PUBLIC_KEY = "encrypting_public_key"
	// SESSION_ENCRYPTION_NAME = "session_encryption_name"

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
		return simulator.GetWithFixedSeedInsecure(1073741825)
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
		return nil, nil, nil, fmt.Errorf("Unknown Hash Algorithm for TPM PCRs %v", algo)
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

const maxDigestBuffer = 1024

func encryptDecryptSymmetric(rwr transport.TPM, keyAuth tpm2.AuthHandle, iv, data []byte, sess tpm2.Session, decrypt bool) ([]byte, error) {
	var out, block []byte

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: keyAuth,
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    tpm2.TPMAlgCFB,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(rwr, sess)
		if err != nil {
			return nil, err
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
}

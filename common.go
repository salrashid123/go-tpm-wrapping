package tpmwrap

const (
	EnvTPMPath             = "TPM_PATH"
	EnvPCRS                = "TPM_PCRS"
	EnvPCRValues           = "TPM_PCR_VALUES"
	EnvEncryptingPublicKey = "TPM_ENCRYPTING_PUBLIC_KEY"

	TPM_PATH              = "tpm_path"
	PCRS                  = "pcrs"
	PCR_VALUES            = "pcr_values"
	ENCRYPTING_PUBLIC_KEY = "encrypting_public_key"
)

const (
	TPMSeal = iota
	TPMImport
)

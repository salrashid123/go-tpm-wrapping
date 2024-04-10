package tpmwrap

const (
	EnvTPMPath             = "TPM_PATH"
	EnvPCRS                = "TPM_PCRS"
	EnvPCRValues           = "TPM_PCR_VALUES"
	EnvEncryptingPublicKey = "TPM_ENCRYPTING_PUBLIC_KEY"
)

const (
	TPMSeal = iota
	TPMImport
)

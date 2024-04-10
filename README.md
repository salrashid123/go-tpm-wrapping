
## Go-TPM-Wrapping - Go library for encrypting values through Trusted Platform Module (TPM)

Library to encrypt and decrypt data using a Trusted Platform Module (TPM).

This is a a variation of

* [https://github.com/hashicorp/go-kms-wrapping](https://github.com/hashicorp/go-kms-wrapping)

which will [Seal/Unseal using a TPM's Storage Root Key (SRK)](https://github.com/salrashid123/tpm2/tree/master/srk_seal_unseal)

To use this, you must have access to a TPM.  When you encrypt data, it can ONLY get decrypted by that *SAME* TPM.


>> This library is NOT supported by google

### Usage

To use, simply initialize the wrapper as shown below, specify a path to the TPM and optionally the PCR values to bind against

```golang

import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
)

	wrapper := tpmwrap.NewWrapper()
	_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		"tpm_path": "/dev/tpm0",
		"pcrs":     "23",
	}))

	blobInfo, err := wrapper.Encrypt(ctx, []byte("foo"))

	fmt.Printf("Encrypted: %s\n", hex.EncodeToString(blobInfo.Ciphertext))

	plaintext, err := wrapper.Decrypt(ctx, blobInfo)
	fmt.Printf("Decrypted %s\n", string(plaintext))
```

See the `example` folder for an example:

```bash
cd example

## encrypt/decrypt
$ go run main.go 
Encrypted: d67b83180ae269a148cb86c2bd69d0cfba55d4
Decrypted foo

## encrypt/decrypt and bind the data to the current values in
### PCR banks 16,23
$ go run main.go --pcrs=16,23
Encrypted: 19d1fd5fefeb37ec0964d2219cf7eeea4b548b
Decrypted foo

## encrypt/decrypt and bind the data to the current values in
### PCR banks 16,23
### Extend PCR bank 23 and attempt to decrypt (which is expected to fail)

$ go run main.go --pcrs=16,23 --extendPCR=23
Encrypted: e886b584b5637006134f2eb1e81d2d679eebee
Decrypted foo
======= Extend PCR  ========
   Current PCR(23) e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7   
   New PCR(23) 31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0Error decrypting failed to unsealing key: failed to certify PCRs: PCR 23 mismatch: expected e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7, got 31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0
exit status 1
```


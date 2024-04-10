
## Go-TPM-Wrapping - Go library for encrypting values through Trusted Platform Module (TPM)

Library to encrypt and decrypt data using a wrapping key thats encoded inside a Trusted Platform Module (TPM).

In other words, you *must* have access to the TPM that encrypted the data to decrypt the wrapping key


There are two modes to using this library:

* Seal/Unseal 

  To use this, you must have access to the *same* TPM for both encrypting and decrypting.

  When you encrypt data, it can ONLY get decrypted by that *SAME* TPM.

  see [Seal/Unseal using a TPM's Storage Root Key (SRK)](https://github.com/salrashid123/tpm2/tree/master/srk_seal_unseal)

* Remote encryption

  To use this, you do not need a TPM to encrypt but you DO need a TPM to decrypt.

  This mode utilizes a TPM Endorsement Public Key (EKPub) to wrap the encryption key which can ONLY get decrypted by the TPM that owns the EKPub

  see [Remote Sealed TPM Import](https://github.com/salrashid123/gcp_tpm_sealed_keys/tree/main?tab=readme-ov-file#sealed-symmetric-key)

This is a a variation of [https://github.com/hashicorp/go-kms-wrapping](https://github.com/hashicorp/go-kms-wrapping)

>> This library is NOT supported by google

### Usage Seal

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
$ go run seal/main.go 
Encrypted: d67b83180ae269a148cb86c2bd69d0cfba55d4
Decrypted foo

## encrypt/decrypt and bind the data to the current values in
### PCR banks 16,23
$ go run seal/main.go --pcrs=16,23
Encrypted: 19d1fd5fefeb37ec0964d2219cf7eeea4b548b
Decrypted foo

## encrypt/decrypt and bind the data to the current values in
### PCR banks 16,23
### Extend PCR bank 23 and attempt to decrypt (which is expected to fail)

$ go run seal/main.go --pcrs=16,23 --extendPCR=23
Encrypted: e886b584b5637006134f2eb1e81d2d679eebee
Decrypted foo
======= Extend PCR  ========
   Current PCR(23) e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7   
   New PCR(23) 31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0Error decrypting failed to unsealing key: failed to certify PCRs: PCR 23 mismatch: expected e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7, got 31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0
exit status 1
```

### Usage Import

To use this mode, you must first acquire the Endorsement Public Key (ekPub). 

The ekPub [can be extracted](https://github.com/salrashid123/tpm2/tree/master/ek_import_blob) from the Endorsement Certificate on a TPM or on GCE, via an API.

To use `tpm2_tools` on the target machine

```bash
$ tpm2_getekcertificate -X -o ECcert.bin

$ openssl x509 -in ECcert.bin -inform DER -noout -text

$ openssl  x509 -pubkey -noout -in ECcert.bin  -inform DER 
```

Copy the public key (ek to a remote host and save as `encrypting_public_key`)

On a remote machine:

```golang
import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
)

		b, err := os.ReadFile(*encrypting_public_key)

		wrapper := tpmwrap.NewRemoteWrapper()
		_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"encrypting_public_key": hex.EncodeToString(b),
			"pcr_values":            "",
		}))

		blobInfo, err := wrapper.Encrypt(ctx, []byte("foo"))

		eb, err := protojson.Marshal(blobInfo)

		err = os.WriteFile(*encrypted_blob, eb, 0644)
```

At this point, copy `encrypted_blob` to the machine with the TPM

On a TPM:

```golang
		wrapper := tpmwrap.NewRemoteWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"tpm_path": *tpmPath,
		}))

		eb, err := os.ReadFile(*encrypted_blob)

		newBlobInfo := &wrapping.BlobInfo{}
		err = protojson.Unmarshal(eb, newBlobInfo)

		plaintext, err := wrapper.Decrypt(ctx, newBlobInfo)
		fmt.Printf("Decrypted %s\n", string(plaintext))

```

See the `example/import` folder.

The following encrypts some data and binds it to a PCR value

```bash
$ go run import/main.go --mode=encrypt  --encrypting_public_key=/tmp/ek.pem   \
   --encrypted_blob=/tmp/encrypted.dat

# now copy scp /tmp/encrypted.dat to VM
```

Then on a machine with the TPM, run

```bash
go run import/main.go --mode=decrypt  --encrypted_blob=/tmp/encrypted.dat
```

This will decrypt the data

Note, if you encrypted the data to a pcr value, extend the PCR value successively will invalidate the key

eg, if the remote system has the following PCRs

```bash
$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

you can encrypt the data and bind it to that PCR:

```bash
$ go run import/main.go --mode=encrypt  --encrypting_public_key=/tmp/ek.pem  \
   --pcrValues="23:f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b" \
   --encrypted_blob=/tmp/encrypted.dat
```

but if you extend it, you can no longer decrypt 

```bash
$ tpm2_pcrextend 23:sha256=0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
$ tpm2_pcrread sha256:23
  sha256:
    23: 0xDB56114E00FDD4C1F85C892BF35AC9A89289AAECB1EBD0A96CDE606A748B5D71
```

and attempt to decrypt the data, it will fail with a policy check:

```bash
$ go run import/main.go --mode=decrypt  --encrypted_blob=/tmp/encrypted.dat
Error decrypting error decrypted key error: unseal failed: session 1, error code 0x1d : a policy check failed
exit status 1
```

As mentioned, you can acquire the ekPub for certain systems like GCP VM's via an API:

```bash
gcloud compute  instances create   tpm-device  \
      --zone=us-central1-a --machine-type=n1-standard-1    --tags tpm  \
	   --no-service-account  --no-scopes  \
	   --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
	   --image-family=debian-11 --image-project=debian-cloud

gcloud compute instances get-shielded-identity  tpm-device --format="value(encryptionKey.ekPub)" > /tmp/ek.pem
```


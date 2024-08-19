## Go-TPM-Wrapping - Go library for encrypting data using Trusted Platform Module (TPM)

Library to encrypt and decrypt data using a wrapping key thats encoded inside a `Trusted Platform Module (TPM)`.

In other words, you *must* have access to a specific TPM decrypt the wrapping key.

In addition you can stipulate that the key can only get decrypted by the TPM if the user provides a passphrase (`userAuth`) or if the target system has certain `PCR` values.

>> **Update 8/16/24**:  changed the key format to use protobuf

There are two modes to using this library:

* `Seal/Unseal` 

  To use this, you must have access to the *same* TPM for both encrypting and decrypting.

  When you encrypt data, it can ONLY get decrypted by that *SAME* TPM.

  see [Seal/Unseal using a TPM's Storage Root Key (SRK)](https://github.com/salrashid123/tpm2/tree/master/srk_seal_unseal)

* `Remote encryption`

  This mode utilizes a TPM `Endorsement Public Key (EKPub)` to wrap the encryption key which can ONLY get decrypted by the TPM that owns the EKPub

  This mode requires local access to a real or simulated TPM to encrypt the data.


This library is a a variation of [https://github.com/hashicorp/go-kms-wrapping](https://github.com/hashicorp/go-kms-wrapping)

You can use this as a library or CLI

>> This library is NOT supported by google

---

Examples below uses two [software TPMs](https://manpages.debian.org/testing/swtpm/swtpm.8.en.html) (`--tpm-path="127.0.0.1:2321"`).  IRL you'd use actual TPMs (`--tpm-path="/dev/tpm0"`).

To configure the software TPM on your laptop for testing, see the `Using swtpm` section below.

---

CLI Options:

| Option | Description |
|:------------|-------------|
| **`-mode`** | operation mode `seal or import` (default: `seal`) |
| **`-encryptedBlob`** | file to decrypt or write encrypted data to (default: `/tmp/encrypted.json`) |
| **`-keyName`** | User set key name (default: `key1`) |
| **`-decrypt`** | toggle if decryption should occur  (default:  `false`) |
| **`-tpmPath`** | path to tpm (default: `/dev/tpmrm0`) |
| **`-keyPass`** | password to seal the key with (default: ``) |
| **`-hierarchyPass`** | password for the hierarchy (if any) (for import it is for the Endorsement; for Seal it is for Owner) (default ``) |
| **`-pcrValues`** | PCR values to bind to (comma separated pcr banks, ascending) (default ``) |
| **`-dataToEncrypt`** | some small text to encrypt (default ``) |
| **`-debug`** | toggle debug mode (default: `false`) |
| **`-encrypting_public_key`** | for Import: path to the PEM public key for the target TPM (default: ``) |
| **`-tpm-session-encrypt-with-name`** | TPM "name" in hex to encrypt TPM sessions against (default: ``) |

---

### CLI

You can build or download the cli from the `Releases` section

```bash
go build  -o go-tpm-wrapping cmd/main.go
```

#### Usage Seal

To use, simply initialize the wrapper as shown below, specify a path to the TPM and optionally the PCR values to bind against

To use as a CLI, you can run `cmd/main.go` or download from the `Releases` page.  If you want to use as an API, see the `example` folder

```bash
## encrypt/decrypt
$ go-tpm-wrapping --mode=seal --debug \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"

$ go-tpm-wrapping --mode=seal --debug --decrypt=true \
   --encryptedBlob=/tmp/encrypted.json --tpm-path="127.0.0.1:2321"

## encrypt/decrypt with passphrase
$ go-tpm-wrapping --mode=seal --debug \
   --dataToEncrypt=foo  --keyPass=testpass --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"

$ go-tpm-wrapping --mode=seal --debug --keyPass=testpass --decrypt=true \
   --encryptedBlob=/tmp/encrypted.json --tpm-path="127.0.0.1:2321"

## encrypt/decrypt with passphrase and PCR values.  
### for example, if you want to stipulate the following PCR values must be present to unseal
$ tpm2_pcrread sha256:0,23
  sha256:
    0 : 0x0000000000000000000000000000000000000000000000000000000000000000
    23: 0x0000000000000000000000000000000000000000000000000000000000000000

## encrypt/decrypt
$ go-tpm-wrapping --mode=seal --debug  \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --keyPass=testpass \
   --pcrValues=0:0000000000000000000000000000000000000000000000000000000000000000,23:0000000000000000000000000000000000000000000000000000000000000000 \
   --tpm-path="127.0.0.1:2321" 

$ go-tpm-wrapping --mode=seal --debug --decrypt=true \
   --encryptedBlob=/tmp/encrypted.json --keyPass=testpass  \
   --tpm-path="127.0.0.1:2321"
```


to verify that pcr values are actually used, increment the PCR after which decryption will fail

```bash
# export TPM2TOOLS_TCTI="swtpm:port=2321"
$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrextend 23:sha256=0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

$ go-tpm-wrapping --mode=seal --debug --decrypt=true \
   --encryptedBlob=/tmp/encrypted.json --keyPass=testpass  \
    --tpm-path="127.0.0.1:2321"

 Error decrypting executing unseal: TPM_RC_POLICY_FAIL (session 1): a policy check failed
```


If you set auth on the owner key, set the `--hierarchyPass=` parameter:

```bash
### set a password on the owner hierarchy
$ export TPM2TOOLS_TCTI="swtpm:port=2321"
$ tpm2_changeauth -c owner newpass

$ go-tpm-wrapping --mode=seal --debug \
   --dataToEncrypt=foo --hierarchyPass=newpass --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"

$ go-tpm-wrapping --mode=seal --debug --hierarchyPass=newpass  --decrypt=true \
   --encryptedBlob=/tmp/encrypted.json --tpm-path="127.0.0.1:2321"
```

If you set auth on the owner key, set the `--hierarchyPass=` parameter:

#### Usage Import

To use this mode, you must first acquire the `Endorsement Public Key (ekPub)`. 

The ekPub [can be extracted](https://github.com/salrashid123/tpm2/tree/master/ek_import_blob) from the `Endorsement Certificate` on a TPM or on GCE, via an API.

To use `tpm2_tools` on the target machine (the one where you want to transfer a key *to*)

```bash
$ tpm2_createek -c /tmp/primaryB.ctx -G rsa -u /tmp/ekB.pub -Q
$ tpm2_readpublic -c /tmp/primaryB.ctx -o /tmp/ekpubB.pem -f PEM -Q

## or from the ekcert
# $ tpm2_getekcertificate -X -o /tmp/ECcert.bin
# $ openssl x509 -in /tmp/ECcert.bin -inform DER -noout -text
# $ openssl x509 -pubkey -noout -in /tmp/ECcert.bin  -inform DER 
```

Copy the public key to the host you want to transfer they key *from*.  This is the `encrypting_public_key`

Just to note, you don't *really* need access to a real, permanent TPM on the system you're transferring from.  You can even use a simulator (`--tpm-path="simulator"`)

The following encrypts some data using just the remote `ekpub`

```bash
## encrypt
$ go-tpm-wrapping --mode=import --debug  \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"
### note, you can even encrypt the data with a --tpm-path="simulator"
### copy scp /tmp/encrypted.json to VM

## decrypt
$ go-tpm-wrapping --mode=import --debug --decrypt --encrypting_public_key=/tmp/ekpubB.pem  \
    --encryptedBlob=/tmp/encrypted.json \
    --tpm-path="127.0.0.1:2341" 
```

- With userAuth

```bash
$ go-tpm-wrapping --mode=import --debug  \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo --keyPass=bar --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"
```

Then on a machine with the TPM, run

```bash
$ go-tpm-wrapping --mode=import --debug --decrypt \
    --encryptedBlob=/tmp/encrypted.json --keyPass=bar \
    --tpm-path="127.0.0.1:2341" 
```

- With PCR

```bash
## encrypt/decrypt and bind the data to the **destination TPM's** values in
### If you want the TPM where you want to decrypt to have the following PCR values

$ tpm2_pcrread sha256:0,23
  sha256:
    0 : 0x0000000000000000000000000000000000000000000000000000000000000000
    23: 0x0000000000000000000000000000000000000000000000000000000000000000

## then just specify them while encrypting
$ go-tpm-wrapping --mode=import --debug  \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo  \
   --pcrValues=0:0000000000000000000000000000000000000000000000000000000000000000,23:0000000000000000000000000000000000000000000000000000000000000000 \
   --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"

## then these PCRs are read in to decrypt on the destination
$ go-tpm-wrapping --mode=import --debug --decrypt  \
   --dataToEncrypt=foo --encrypting_public_key=/tmp/ekpubB.pem --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2341" 
```

For validation, increment the PCR value on `TPM-B`

```bash
export TPM2OPENSSL_TCTI="swtpm:port=2341"
$ tpm2_pcrread sha256:0,23
  sha256:
    0 : 0x0000000000000000000000000000000000000000000000000000000000000000
    23: 0x0000000000000000000000000000000000000000000000000000000000000000

$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrread sha256:0,23
  sha256:
    0 : 0x0000000000000000000000000000000000000000000000000000000000000000
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

# loading the value fails
go-tpm-wrapping --mode=import --decrypt  \
   --dataToEncrypt=foo --encrypting_public_key=/tmp/ekpubB.pem --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2341" 

Error decrypting EncryptSymmetric failed: TPM_RC_POLICY_FAIL (session 1): a policy check failed
```

```bash
### set a password on the owner hierarchy for local and password for the endorsement for remote
export TPM2TOOLS_TCTI="swtpm:port=2321"
tpm2_changeauth -c owner newpass1

export TPM2TOOLS_TCTI="swtpm:port=2341"
tpm2_changeauth -c endorsement newpass2

# encrypt
go-tpm-wrapping --mode=import --hierarchyPass=newpass1  \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"

# decrypt
go-tpm-wrapping --mode=import --hierarchyPass=newpass2 --decrypt --encrypting_public_key=/tmp/ekpubB.pem  \
    --encryptedBlob=/tmp/encrypted.json \
    --tpm-path="127.0.0.1:2341" 
```

### Usage API

If you want to use the api instead of the CLI, see the `example/` folder

#### Seal/Unseal

Encrypt:

```golang
import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
)

	wrapper := tpmwrap.NewWrapper()

	_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		tpmwrap.TPM_PATH:   *tpmPath,
		// tpmwrap.PCR_VALUES: *pcrValues,
		// tpmwrap.USER_AUTH:  *userAuth,
	}))


	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt))

	fmt.Printf("Encrypted: %s\n", hex.EncodeToString(blobInfo.Ciphertext))
```

Decrypt:

```golang
	wrapper := tpmwrap.NewWrapper()

	_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		tpmwrap.TPM_PATH:   *tpmPath,
		// tpmwrap.USER_AUTH:  *userAuth,
	}))

	b, err := os.ReadFile(*encryptedBlob)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo)

	fmt.Printf("Decrypted %s\n", string(plaintext))
```

```bash
# no auth
## encrypt/decrypt
$ go run seal_encrypt/main.go --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
  --tpm-path="127.0.0.1:2321"

$ go run seal_decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
  --tpm-path="127.0.0.1:2321"

# password and pcr
$ go run seal_encrypt/main.go --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --userAuth=abc --pcrValues=23:0000000000000000000000000000000000000000000000000000000000000000 \
    --tpm-path="127.0.0.1:2321"

$ go run seal_decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
   --userAuth=abc  \
    --tpm-path="127.0.0.1:2321"
```


#### Import

API usage for import on the local machine is (the one where you want to transfer a secret *from*)

```golang
import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
)

	wrapper := tpmwrap.NewRemoteWrapper()

	_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		tpmwrap.TPM_PATH:              *tpmPath,
		tpmwrap.ENCRYPTING_PUBLIC_KEY: hex.EncodeToString(b),
		// tpmwrap.PCR_VALUES:            *pcrValues,
		// tpmwrap.USER_AUTH:             *userAuth,
	}))

	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt))

	eb, err := protojson.Marshal(blobInfo)

	fmt.Printf("Encrypted: %s\n", hex.EncodeToString(blobInfo.Ciphertext))
```

At this point, copy `encrypted_blob` to the machine where you want to transfer a key *to*

```golang
	wrapper := tpmwrap.NewRemoteWrapper()

	_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		tpmwrap.TPM_PATH:              *tpmPath,
		tpmwrap.ENCRYPTING_PUBLIC_KEY: hex.EncodeToString(b),
		// tpmwrap.USER_AUTH:             *userAuth,
	}))

	eb, err := os.ReadFile(*encryptedBlob)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(eb, newBlobInfo)

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo)

	fmt.Printf("Decrypted %s\n", string(plaintext))

```

```bash
# no auth
$ go run import_encrypt/main.go --dataToEncrypt=foo \
   --encryptedBlob=/tmp/encrypted.json --encrypting_public_key=/tmp/ekpubB.pem \
   --tpm-path="127.0.0.1:2321"

$ go run import_decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
   --encrypting_public_key=/tmp/ekpubB.pem --tpm-path="127.0.0.1:2341"

# password 
$ go run import_encrypt/main.go --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --userAuth=abc \
   --tpm-path="127.0.0.1:2321"

$ go run import_decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --userAuth=abc \
   --tpm-path="127.0.0.1:2341"

# pcr 
$ go run import_encrypt/main.go --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --pcrValues=23:0000000000000000000000000000000000000000000000000000000000000000 \
   --tpm-path="127.0.0.1:2321"

$ go run import_decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --tpm-path="127.0.0.1:2341"   
```


### Session Encryption

Each operation uses encrypted sessions but by default, the library interrogates the TPM for the current EK directly.

A todo is to allow the user to specify the 'name' of a trusted EK which we'd compare in code (if not match, bail, eg implement the ` --tpm-session-encrypt-with-name=` parameter shown below) 

* [tpmrand Encrypted Session](https://github.com/salrashid123/tpmrand?tab=readme-ov-file#encrypted-session)]
* [aws-tpm-process-credential Encrypted Sessions](https://github.com/salrashid123/aws-tpm-process-credential?tab=readme-ov-file#encrypted-tpm-sessions)
* [salrashid123/tpm2/Session Encryption](https://github.com/salrashid123/tpm2/tree/master/tpm_encrypted_session)


### Build

If you want to regenerate with protoc:

```bash
$ /usr/local/bin/protoc --version
   libprotoc 25.1

$ go get -u github.com/golang/protobuf/protoc-gen-go   

$ /usr/local/bin/protoc -I ./ --include_imports \
   --experimental_allow_proto3_optional --include_source_info \
   --descriptor_set_out=tpmwrappb/wrap.proto.pb  \
   --go_out=paths=source_relative:. tpmwrappb/wrap.proto
```

### Seal/Import with non-EKPub

_TODO_

The default mode for "import" utilizes the Endorsement Public key.  A TODO is to allow _any_ encryption key you trust on the target TPM (`TPM-B`).

You would create an arbitrary encryption-only key using something like the following and evict it to a persistent handle as shown below on `TPM-B`


```bash
export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"
tpm2_pcrread sha256:0,23

## create "H2 Template" as primary, you can setup any primary you want
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt"
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx

echo "meet me at..." > secret.txt
tpm2_rsaencrypt -c key.ctx   -o secret.txt.enc secret.txt
tpm2_rsadecrypt -c key.ctx -o secret.txt.dec  secret.txt.enc

tpm2_flushcontext -t

## cant' use this key for signing
## tpm2_sign -c key.ctx -g sha256 -o sig.rssa secret.txt

tpm2_readpublic -c key.ctx -o /tmp/pubA.pem -f PEM -Q
tpm2_evictcontrol -C o -c key.ctx 0x81010001
```

Copy `/tmp/pubA.pem` to `TPM-A` and start the import. 

Copy the `encryptedblob.json` to `TPM-B`.  Specify the persistent handle while importing on `TPM-B` (eg, use (`--mode=import --parentHandle=0x81010001`))

---

### Background

The following details some background how each of these modes works:

- `Seal`

  Sealing data to a TPM is pretty well known (see [tpm2_unseal](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_unseal.1.md)).  Basically you create a key where the sensitive data within that key is the actual secret.   The Key itself can have a password or pcr policy set which must get fulfilled to unseal.  In this library, the wrapping DEK is what is sealed.

- `Import`

   For this,  you encrypt some data _remotely_ using just a public encryption key for the target TPM.
   
   In this specific implementation, there ar e several layers of encryption involved:


To transfer a secret from `TPM-A` to `TPM-B` with userAuth

* `TPM-B`: create `ekpubB.pem`
*   copy `ekpubB.pem` to `TPM-A`
* on `TPM-A`:
* - create a trial session with `PolicyDuplicateSelect` using `TPM-B`'s ekpub
* - create an AES key on `TPM-A` with authPolicy (userAuth) and the trial session.
* - use the AES key to encrypt the DEK
* - duplicate the TPM based key using the `Policyduplicateselect` and a real session

copy the duplicated key and wrapped DEK to `TPM-B`

* on `TPM-B`:
* - create a real session with `PolicySecret` (since we used the EndorsementKey)
* - Import and Load the duplicated key with the policy
* - Use the TPM-based key, specify the userAuth and decrypt the DEK

To transfer a secret from `TPM-A` to `TPM-B` with `PCRPolicy`

* TPM-B: create `ekpubB.pem`
*   copy `ekpubB.pem` to `TPM-A`
* on `TPM-A`:
* - create random local (non-tpm) AES key
* - use the AES key to encrypt the DEK
* - create a trial TPM `PolicyOR` session with a `PolicyPCR` and `PolicyDuplicateSelect` (the latter which bound to `TPM-B`'s ekpub)
* - create a NEW AES key on `TPM-A` with the original random AES key as the sensitive bit and the AuthPolicy using the `PolicyOR` above.
* - create a real session with `PolicyDuplicateSelect` bound to the remote `TPM-B`
* - duplicate the key

copy the duplicated key to `TPM-B`

* on `TPM-B`
* - Create a `PolicyOR` with `PolicyPCR` and `PolicyDuplicateSelect` that match what is expected
* - Import the duplicated key
* - Decrypt the KEK using the TPM-based duplicated key (eg the AES key)
* - Use the KEK to decrypt the DEK

---

### Using swtpm

If you want to test locally with software TPMs:

```bash
### start two emulators 

## TPM-A
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

## TPM-B
rm -rf /tmp/myvtpm2 && mkdir /tmp/myvtpm2
sudo swtpm_setup --tpmstate /tmp/myvtpm2 --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=/tmp/myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear


### For TPM-A
export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
tpm2_pcrread sha256:0,23
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_createek -c /tmp/primaryA.ctx -G rsa  -Q
tpm2_readpublic -c /tmp/primaryA.ctx -o /tmp/ekpubA.pem -f PEM -Q
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

## for import create ek on TPM-B
export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"
tpm2_pcrread sha256:0,23

tpm2_createek -c /tmp/primaryB.ctx -G rsa  -Q
tpm2_readpublic -c /tmp/primaryB.ctx -o /tmp/ekpubB.pem -f PEM -Q
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

`swtpm` does not include a resource manager so you may need to run `tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l`

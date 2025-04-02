## Go-TPM-Wrapping - Go library for encrypting data using Trusted Platform Module (TPM)

Library to encrypt and decrypt data using a wrapping key thats encoded inside a `Trusted Platform Module (TPM)`.

In other words, you *must* have access to a specific TPM decrypt the wrapping key.

In addition you can stipulate that the key can only get decrypted by the TPM if the user provides a passphrase (`userAuth`) or if the target system has certain `PCR` values.

>> **Update 11/18/24**: `v0.7.0`:changed import protobuf to use seal/unseal

>> **Update 8/16/24**:  changed the key format to use protobuf

There are two modes to using this library:

* `Seal/Unseal` 

  To use this, you must have access to the *same* TPM for both encrypting and decrypting.

  When you encrypt data, it can ONLY get decrypted by that *SAME* TPM.

  see [Seal/Unseal using a TPM's Storage Root Key (SRK)](https://github.com/salrashid123/tpm2/tree/master/srk_seal_unseal)

* `Remote encryption`

  This mode utilizes a TPM `Endorsement Public Key (EKPub)` to wrap the some data which can ONLY get decrypted by the TPM that owns the EKPub

  This mode requires local access to a real or simulated TPM to encrypt the data.


For a detailed description on how these modes work, see the [Background](#background) section at the end

This library builds off of Hashicorp Vault wrapping [https://github.com/hashicorp/go-kms-wrapping](https://github.com/hashicorp/go-kms-wrapping).

You can use this as a library or CLI

>> This library is NOT supported by google

---

Examples below uses two [software TPMs](https://manpages.debian.org/testing/swtpm/swtpm.8.en.html) (`--tpm-path="127.0.0.1:2321"`).  IRL you'd use actual TPMs (`--tpm-path="/dev/tpm0"`).

To configure the software TPM on your laptop for testing, see the `Using swtpm` section below.

---

### CLI

You can build or download the cli from the `Releases` section

```bash
go build  -o go-tpm-wrapping cmd/main.go
```

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

#### Usage Seal

To use, simply initialize the wrapper as shown below, specify a path to the TPM and optionally the PCR values to bind against

To use as a CLI, you can run `cmd/main.go` or download from the [Releases](/releases) page.  If you want to use as an API, see the [example/](/tree/main/example) folder

The following uses a software TPM (`swtpm`) which you can configure with the instructions provided at the end.  In real life you'd use a real TPM (`--tpm-path=/dev/tpmrm0`)

- **encrypt/decrypt**

```bash
$ go-tpm-wrapping --mode=seal --debug \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"

$ go-tpm-wrapping --mode=seal --debug --decrypt=true \
   --encryptedBlob=/tmp/encrypted.json --tpm-path="127.0.0.1:2321"
```

- **encrypt/decrypt with passphrase**

```bash
$ go-tpm-wrapping --mode=seal --debug \
   --dataToEncrypt=foo  --keyPass=testpass --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"

$ go-tpm-wrapping --mode=seal --debug --keyPass=testpass --decrypt=true \
   --encryptedBlob=/tmp/encrypted.json --tpm-path="127.0.0.1:2321"
```

- **encrypt/decrypt with passphrase and PCR values**

```bash
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

To use this mode, you must first acquire the `RSA Endorsement Public Key (ekPub)`.   At the moment only RSA keys are supported (a todo is EC)

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

- **encrypt/decrypt**

The following uses a local software TPM to generate and encrypt the transfer key but you can just as easily use a simulator instead `--tpm-path="simulator"`.  To decrypt you would need to specify a TPM (swtpm or real)

```bash
# encrypt
$ go-tpm-wrapping --mode=import --debug  \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"
```

- copy scp `/tmp/encrypted.json` to VM

```bash
# decrypt
$ go-tpm-wrapping --mode=import --debug --decrypt --encrypting_public_key=/tmp/ekpubB.pem  \
    --encryptedBlob=/tmp/encrypted.json \
    --tpm-path="127.0.0.1:2341" 
```

- **With userAuth**

```bash
# encrypt
$ go-tpm-wrapping --mode=import --debug  \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo --keyPass=bar --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"
```

Then on a machine with the TPM, run

```bash
# decrypt
$ go-tpm-wrapping --mode=import --debug --decrypt \
    --encryptedBlob=/tmp/encrypted.json --keyPass=bar \
    --tpm-path="127.0.0.1:2341" 
```

- **With PCR**

```bash
## encrypt/decrypt and bind the data to the **destination TPM's** values in
### If you want the TPM where you want to decrypt to have the following PCR values
export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"
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
```

then,

```bash
# decrypt
## then these PCRs are read in to decrypt on the destination
$ go-tpm-wrapping --mode=import --debug --decrypt  \
   --dataToEncrypt=foo --encrypting_public_key=/tmp/ekpubB.pem --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2341" 
```

For validation, increment the PCR value on `TPM-B`

```bash
export TPM2TOOLS_TCTI="swtpm:port=2341"
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

If the local or remote TPM has a passphrase for the Owner or Endorsement key, you can specify  the `--hierarchyPass=` parameter:


```bash
## if the local owner key has a passphrase set
export TPM2TOOLS_TCTI="swtpm:port=2321"
tpm2_changeauth -c owner newpass1

## if the remote has a passphrase on the endorsement key
export TPM2TOOLS_TCTI="swtpm:port=2341"
tpm2_changeauth -c endorsement newpass2

# encrypt and specify the local 
go-tpm-wrapping --mode=import --hierarchyPass=newpass1  \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2321"

# decrypt and specify the remote
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
	// you can also use options: wrapper.SetConfig(ctx, WithTPM(*tpmPath))
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

	// you can also use options: wrapper.SetConfig(ctx, WithTPM(*tpmPath), WithEncryptingPublicKey(hex.EncodeToString(b)))
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

Each operation uses [encrypted sessions](https://trustedcomputinggroup.org/wp-content/uploads/TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation_8May23-3.pdf) by default and interrogates the TPM for the current EK directly.

If for whatever reason you want to specify the "name" of the EK to to use, set the `--tpm-session-encrypt-with-name=` parameter shown below


```bash
# for tpmA
tpm2_createek -c /tmp/primaryA.ctx -G rsa  -Q
tpm2_readpublic -c /tmp/primaryA.ctx -o /tmp/ekpubA.pem -n /tmp/ekpubAname.bin -f PEM -Q
xxd -p -c 100 /tmp/ekpubAname.bin 
   000b47ab97fdda365cbb86a37548e38468f72e8baccc633cffc42402183679956608

# Then use the hex value returned in the --tpm-session-encrypt-with-name= argument.
   --tpm-session-encrypt-with-name=000b47ab97fdda365cbb86a37548e38468f72e8baccc633cffc42402183679956608
```

### Verify Binary Attestation

`go-tpm-wrapping` release binaries are generated using github workflow and golreaser.  Part of that flow generates github attestation reportsat


* [https://github.com/salrashid123/go-tpm-wrapping/attestations](https://github.com/salrashid123/go-tpm-wrapping/attestations)

which you can use to verify end-to-end provence

```bash
$ wget https://github.com/salrashid123/go-tpm-wrapping/releases/download/v0.7.7/go-tpm-wrapping_0.7.7_linux_amd64
$ wget https://github.com/salrashid123/go-tpm-wrapping/attestations/4912486/download -O salrashid123-go-tpm-wrapping-attestation-4912486.json

$ gh attestation verify --owner salrashid123 --bundle salrashid123-go-tpm-wrapping-attestation-4912486.json go-tpm-wrapping_0.7.7_linux_amd64 

      Loaded digest sha256:b41bdd15c978353a0ebd088431f47663ebb845e4cd1ea4abc639d3748fa6866f for file://go-tpm-wrapping_0.7.7_linux_amd64
      Loaded 1 attestation from salrashid123-go-tpm-wrapping-attestation-4912486.json

      The following policy criteria will be enforced:
      - Predicate type must match:................ https://slsa.dev/provenance/v1
      - Source Repository Owner URI must match:... https://github.com/salrashid123
      - Subject Alternative Name must match regex: (?i)^https://github.com/salrashid123/
      - OIDC Issuer must match:................... https://token.actions.githubusercontent.com

      ✓ Verification succeeded!

      The following 1 attestation matched the policy criteria

      - Attestation #1
      - Build repo:..... salrashid123/go-tpm-wrapping
      - Build workflow:. .github/workflows/release.yaml@refs/tags/v0.7.7
      - Signer repo:.... salrashid123/go-tpm-wrapping
      - Signer workflow: .github/workflows/release.yaml@refs/tags/v0.7.7
```

### Background

The following details some background how each of these modes works:

#### `Seal`

  Sealing data to a TPM is pretty well known (see [tpm2_unseal](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_unseal.1.md)).  Basically you create a key where the sensitive data within that key is the actual secret.   The Key itself can have a password or pcr policy set which must get fulfilled to unseal.  In this library, the wrapping DEK is what is sealed.

to `Encrypt`:

   1. given plaintext, use [go-kms-wrapping.Encrypt()](https://pkg.go.dev/github.com/hashicorp/go-kms-wrapping#Envelope.Encrypt) to encrypt.
      This will return a new _inner encryption key_, initialization vector and cipher text
   2. generate a primary key on the TPM
   3. create a session or pcr policy to apply to the TPM 
   4. generate child key on the TPM with any policy and set its "sensitive" data to _inner encryption key_
   5. convert the child TPM key to a PEM encoded format
   6. create a protobuf that contains the encoded keyfile
   7. return the ciphertext, initialization vector and encoded tpm key

   ```
   key1, ciphertext1, iv1: = go-kms-wrapping.Encrypt(plaintext1) 
   tpm_key = tpm2_seal(key1)
   ```

to `Decrypt`:

   1. read the ciphertext, IV and encoded tpm key
   2. generate a primary key on the TPM
   3. create a session or pcr policy to apply to the TPM 
   4. load the encoded tpm key
   5. unseal the tpm key to acquire the _inner encryption key_
   6. use the inner key, IV and ciphertext to run [go-kms-wrapping.Decrypt()](https://pkg.go.dev/github.com/hashicorp/go-kms-wrapping#Envelope.Decrypt)
   7. return the plaintext

   ```
   key1 = tpm_key.unseal()
   plaintext1 = go-kms-wrapping.Decrypt(key1, iv1, ciphertext1) 
   ```

#### `Import`

   For this,  you encrypt some data _remotely_ using just a public encryption key for the target TPM.
   
**A**: To transfer a secret from `TPM-A` to `TPM-B` with **userAuth** or **PCRPolicy**

   1. `TPM-B`: create `ekpubB.pem`
   2.  copy `ekpubB.pem` to `TPM-A`

on `TPM-A`:

   3. given plaintext, use [go-kms-wrapping.Encrypt()](https://pkg.go.dev/github.com/hashicorp/go-kms-wrapping#Envelope.Encrypt) to encrypt.
      This will return a new _inner encryption key_ (`env.Key`), initialization vector and cipher text
   4. create a trial session with `PolicyDuplicateSelect` using `TPM-B`'s ekpub
   5. create a TPM key of type `tpm2.TPMAlgKeyedHash` on `TPM-A` with userAuth+`PolicyDuplicateSelect` or as `PolicyOr[PolicyDuplicateSelect||PolicyPCR]`.
   6. set the `env.Key` as the TPM keys sensitive part (i.,e seal data)
   7. duplicate the TPM based key using the `Policyduplicateselect` and a real session

   ```bash
   env.key, ciphertext1, iv1: = go-kms-wrapping.Encrypt(plaintext1) 
   tpm_key = new tpm2_create(auth=with_auth_policy, type=tpm2.TPMAlgKeyedHash, sensitive=env.key)
   duplicate = tpm2_duplicate(tpm_key, ekPubB.pem)
   ```

copy the duplicated key and wrapped ciphertext1, iv1 to `TPM-B`  (all of which is encoded into one file)

on `TPM-B`:

   8. create a real session with `PolicySecret` (since we used the EndorsementKey)
   9. Import and Load the duplicated key with the policy
   10. Use the TPM-based key, specify the userAuth  or `PolicyPCR`and unseal the  _inner encryption key (`env.Key`)

   ```bash
   tpm_key = tpm2_import(duplicate)
   env.key = tpm2_unseal(ciphertext2)
   plaintext1 = go-kms-wrapping.Decrypt(env.key, iv1, ciphertext1) 
   ```

If you want to see the full flow on how the import function works to transfer a key from A to B,

- Initialize

```bash
## Initialize TPM-A
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

## Initialize TPM-B
rm -rf /tmp/myvtpm2 && mkdir /tmp/myvtpm2
sudo swtpm_setup --tpmstate /tmp/myvtpm2 --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=/tmp/myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear
```


- on `TPM-B`, export `EkPub`

```bash
export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"
tpm2_pcrread sha256:0,23

tpm2_createek -c /tmp/primaryB.ctx -G rsa  -u /tmp/ekB.pub -Q
tpm2_readpublic -c /tmp/primaryB.ctx -o /tmp/ekpubB.pem -n /tmp/ekpubBname.bin -f PEM -Q
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_print -t TPM2B_PUBLIC /tmp/ekB.pub  
```

- On `TPM-A`, create key to transfer

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

## load TPM-B's ekpub and get its 'name'
tpm2_loadexternal -C o -u /tmp/ekB.pub  -c new_parent.ctx -n dst_n.name

## create an H2 primary
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat 

### then PCR
tpm2_pcrread -o pcr23_valA.bin "sha256:23" 
xxd -c 100 -p pcr23_valA.bin
tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l "sha256:23" -f pcr23_valA.bin -L policyA_pcr.dat 
tpm2_flushcontext session.dat
rm session.dat

## now create a key with policyduplicateselect
tpm2_startauthsession -S session.dat
tpm2_policyduplicationselect -S session.dat  -N dst_n.name -L policyA_dupselect.dat 
tpm2_flushcontext session.dat
rm session.dat

### create an OR policy together
tpm2_startauthsession -S session.dat
tpm2_policyor -S session.dat -L policyA_or.dat sha256:policyA_pcr.dat,policyA_dupselect.dat 
tpm2_flushcontext session.dat

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

echo "my sealed data" > seal.dat

tpm2_create -C primary.ctx -i seal.dat -u key.pub -r key.priv -a "userwithauth"  -L policyA_or.dat -p foo
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_load -C primary.ctx -r key.priv -u key.pub -c key.ctx
tpm2_readpublic -c key.ctx -o dup.pub
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

## now duplicate
tpm2_startauthsession --policy-session -S session.dat
tpm2_readpublic -c key.ctx -n dupkey.name
tpm2_policyduplicationselect -S session.dat  -N dst_n.name -L policyA_dupselect.dat  -n dupkey.name
tpm2_policyor -S session.dat -L policyA_or.dat sha256:policyA_pcr.dat,policyA_dupselect.dat 
tpm2_duplicate -C new_parent.ctx -c key.ctx -G null  -p "session:session.dat" -r dup.dup -s dup.seed -a "userwithauth"

### these dup* bits are what get encoded into 
###  https://github.com/salrashid123/go-tpm-wrapping/blob/main/tpmwrappb/wrap.proto#L33
cp dup.dup /tmp
cp dup.seed /tmp/
cp dup.pub /tmp/
```

- `TPM-B` load the key and unseal

```bash
export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement

tpm2_import -C /tmp/primaryB.ctx -u /tmp/dup.pub -i /tmp/dup.dup -r dup.prv -s /tmp/dup.seed --parent-auth session:session.ctx

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement

tpm2_load -C /tmp/primaryB.ctx -c imported_key.ctx -u /tmp/dup.pub -r dup.prv  --auth session:session.ctx
tpm2_print -t TPM2B_PUBLIC /tmp/dup.pub

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_pcrread -o pcr23_valA.bin "sha256:23" 
xxd -c 100 -p pcr23_valA.bin
tpm2_startauthsession --policy-session  -S session.dat
tpm2_policypcr -S session.dat -l "sha256:23" -f pcr23_valA.bin -L policyA_pcr.dat 
tpm2_flushcontext session.dat

tpm2_startauthsession --policy-session  -S session.dat
tpm2_policyduplicationselect -S session.dat  -N /tmp/ekpubBname.bin -L policyA_dupselect.dat
tpm2_flushcontext session.dat

tpm2_startauthsession --policy-session -S session.dat
tpm2_policypcr -S session.dat -l "sha256:23" -f pcr23_valA.bin -L policyA_pcr.dat 
tpm2_policyor -S session.dat -L policyA_or.dat sha256:policyA_pcr.dat,policyA_dupselect.dat 

tpm2_unseal -o unseal.dat -c imported_key.ctx -p "session:session.dat+foo" 
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

cat unseal.dat
  my sealed data
```

---

also see

* [tpmrand Encrypted Session](https://github.com/salrashid123/tpmrand?tab=readme-ov-file#encrypted-session)
* [aws-tpm-process-credential Encrypted Sessions](https://github.com/salrashid123/aws-tpm-process-credential?tab=readme-ov-file#encrypted-tpm-sessions)
* [salrashid123/tpm2/Session Encryption](https://github.com/salrashid123/tpm2/tree/master/tpm_encrypted_session)


#### Build

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

#### Verify Release Binary

```bash
gpg --keyserver keys.openpgp.org --recv-keys 3FCD7ECFB7345F2A98F9F346285AEDB3D5B5EF74

## to verify the checksum file for a given release:
wget https://github.com/salrashid123/go-tpm-wrapping/releases/download/v0.7.5/go-tpm-wrapping_0.7.5_linux_amd64
wget https://github.com/salrashid123/go-tpm-wrapping/releases/download/v0.7.5/go-tpm-wrapping_0.7.5_linux_amd64.sig

gpg --verify go-tpm-wrapping_0.7.5_linux_amd64.sig go-tpm-wrapping_0.7.5_linux_amd64
```

#### Seal/Import with non-EKPub

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

#### Using swtpm

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
tpm2_readpublic -c /tmp/primaryA.ctx -o /tmp/ekpubA.pem -n /tmp/ekpubAname.bin -f PEM -Q
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

## for import create ek on TPM-B
export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"
tpm2_pcrread sha256:0,23

tpm2_createek -c /tmp/primaryB.ctx -G rsa  -Q
tpm2_readpublic -c /tmp/primaryB.ctx -o /tmp/ekpubB.pem -n /tmp/ekpubBname.bin -f PEM -Q
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

`swtpm` does not include a resource manager so you may need to run `tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l`

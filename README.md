## AEAD encryption using Trusted Platform Module (TPM)

Library to [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) encrypt and decrypt data using a wrapping key thats encoded using a `Trusted Platform Module (TPM)`.

In other words, you *must* have access to a specific TPM decrypt the wrapping key.

In addition you can stipulate that the key can only get decrypted by the TPM if the user provides a passphrase or if the target system has certain `PCR` values.

This library builds off of Hashicorp Vault wrapping [https://github.com/hashicorp/go-kms-wrapping](https://github.com/hashicorp/go-kms-wrapping).

There are two modes to using this library:

---

* **Seal/Unseal**

  To use this, you must have access to the *same* TPM for both encrypting and decrypting.

  When you encrypt data, it can ONLY get decrypted by that *SAME* TPM:

Encrypt:

1. generate aead `key`
2. `ciphertext = AEAD_Encrypt( key, plaintext )`
3. `sealed_key = TPM_Seal( key )` 


Decrypt:

4. `encryptionKey = TPM_Unseal( sealed_key )`
5. `plaintext = AEAD_Decrypt( key, ciphertext )`

---

* **Remote encryption**

  This mode utilizes a TPM `Endorsement Public Key (EKPub)` to wrap the some data which can ONLY get decrypted by the TPM that owns the EKPub

  This mode does not require access to a local TPM to encrypt data but does require access to the target TPM to decrypt.

  If Bob wants wants to encrypt data for Alice who has a TPM,

   Alice generates `Encorsement Public Key` keypair (`ekPub`)
   
   Alice shares `ekPub.pem` with Bob

Encrypt (Bob):

1. generate aead `key`
2. `ciphertext = AEAD_Encrypt( key, plaintext )`
3. `sealed_key = TPM_Seal( key )`
4. `duplicate_key = TPM_Duplicate( EKPub, sealed_key )`

Decrypt (Alice):

5. `sealed_key = TPM_Import( duplicate_key )`
6. `key = TPM_Unseal( sealed_key )`
7. `plaintext = AEAD_Decrypt( key, ciphertext )`  

---

For a detailed description on how these modes work, see the [Background](#background) section at the end

You can use this as a library or CLI

>> This library is NOT supported by google

---

Examples below uses two [software TPMs](https://manpages.debian.org/testing/swtpm/swtpm.8.en.html) (`--tpm-path="127.0.0.1:2341"`).  IRL you'd use actual TPMs (`--tpm-path="/dev/tpm0"`).

To configure the software TPM on your laptop for testing, see the `Using swtpm` section below.


---

Note that this repo will transfer some arbitrary data that is decrypted on the remote system and is visible in userspace.  If on the other hand you want to transfer a an RSA/AES/HMAC key _into_ the destination TPM without ever being visible, see

* [tpmcopy: Transfer RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)](https://github.com/salrashid123/tpmcopy)

Also, if you are interested in a similar wrapping library based off of ML-KEM, see

* [AEAD encryption using Post Quantum Cryptography (ML-KEM)](https://github.com/salrashid123/go-pqc-wrapping/tree/main)

---

* [Usage](#usage)
  - [CLI](#cli)
    - [Usage Seal](#usage-seal)
    - [Usage Import](#usage-import)  
  - [Usage API](#usage-api)  
    - [Seal/Unseal](#sealunseal)
    - [Import](#import)
* [Options](#options)
  - [ClientData](#client-data)
  - [Session Encryption](#session-encryption)
  - [Wrapped Key format](#wrapped-key-format)
    - [Seal Key Format](#seal-key-format)
    - [Import Key Format](#import-key-format)
    - [Versions](#versions)
* [Verify Binary Attestation](#verify-binary-attestation)
* [Background](#background)

---

## Usage

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
| **`-aad`** | Additional data (default: ``) |
| **`-out`** | Write decrypted data to file (default: `stdout`) |
| **`-clientData`** | JSON to include as client_data (default ``) |
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
go-tpm-wrapping --mode=seal --aad=myaad  \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2341"

go-tpm-wrapping --mode=seal --aad=myaad  --decrypt \
   --encryptedBlob=/tmp/encrypted.json --tpm-path="127.0.0.1:2341"
```

- **encrypt/decrypt with passphrase**

```bash
go-tpm-wrapping --mode=seal --aad=myaad  \
   --dataToEncrypt=foo  --keyPass=testpass --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2341"

go-tpm-wrapping --mode=seal --keyPass=testpass --decrypt --aad=myaad \
   --encryptedBlob=/tmp/encrypted.json --tpm-path="127.0.0.1:2341"
```

- **encrypt/decrypt with passphrase and PCR values**

```bash
### for example, if you want to stipulate the following PCR values must be present to unseal
$ tpm2_pcrread sha256:0,23
  sha256:
    0 : 0x0000000000000000000000000000000000000000000000000000000000000000
    23: 0x0000000000000000000000000000000000000000000000000000000000000000

## encrypt/decrypt
$ go-tpm-wrapping --mode=seal --aad=myaad  \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --keyPass=testpass \
   --pcrValues=0:0000000000000000000000000000000000000000000000000000000000000000,23:0000000000000000000000000000000000000000000000000000000000000000 \
   --tpm-path="127.0.0.1:2341" 

$ go-tpm-wrapping --mode=seal  --decrypt --aad=myaad \
   --encryptedBlob=/tmp/encrypted.json --keyPass=testpass  \
   --tpm-path="127.0.0.1:2341"
```

to verify that pcr values are actually used, increment the PCR after which decryption will fail

```bash
# export TPM2TOOLS_TCTI="swtpm:port=2341"
$ tpm2_pcrread sha256:23
  sha256:
    23: 0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrextend 23:sha256=0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

$ go-tpm-wrapping --mode=seal  --decrypt --aad=myaad \
   --encryptedBlob=/tmp/encrypted.json --keyPass=testpass  \
    --tpm-path="127.0.0.1:2341"

 Error decrypting executing unseal: TPM_RC_POLICY_FAIL (session 1): a policy check failed
```

You can also specify the specific pcr's you expect during decryption. if the pcr values are different (eg )

```bash
$ go-tpm-wrapping --mode=seal  --decrypt --aad=myaad \
   --encryptedBlob=/tmp/encrypted.json --keyPass=testpass  \
   --pcrValues=0:0000000000000000000000000000000000000000000000000000000000000000,23:0000000000000000000000000000000000000000000000000000000000000000 \
   --tpm-path="127.0.0.1:2341"

 Error decrypting executing PolicyPCR: TPM_RC_VALUE (parameter 1): value is out of range or is not correct for the context  
```

If you set auth on the owner key, set the `--hierarchyPass=` parameter:

```bash
### set a password on the owner hierarchy
$ export TPM2TOOLS_TCTI="swtpm:port=2341"
$ tpm2_changeauth -c owner newpass

$ go-tpm-wrapping --mode=seal --aad=myaad \
   --dataToEncrypt=foo --hierarchyPass=newpass --encryptedBlob=/tmp/encrypted.json \
   --tpm-path="127.0.0.1:2341"

$ go-tpm-wrapping --mode=seal  --hierarchyPass=newpass  --decrypt --aad=myaad \
   --encryptedBlob=/tmp/encrypted.json --tpm-path="127.0.0.1:2341"
```

If you set auth on the owner key, set the `--hierarchyPass=` parameter:

#### Usage Import

To use this mode, you must first acquire the `RSA Endorsement Public Key (ekPub)`.   At the moment only RSA keys are supported (a todo is EC)

The ekPub [can be extracted](https://github.com/salrashid123/tpm2/tree/master/ek_import_blob) from the `Endorsement Certificate` on a TPM or on GCE, via an API.

To use `tpm2_tools` on the target machine (the one where you want to transfer a key *to*)

```bash
tpm2_createek -c /tmp/primaryB.ctx -G rsa -u /tmp/ekB.pub -Q
tpm2_readpublic -c /tmp/primaryB.ctx -o /tmp/ekpubB.pem -f PEM -Q
tpm2_flushcontext -t

## or from the ekcert
# tpm2_getekcertificate -X -o /tmp/ECcert.bin
# openssl x509 -in /tmp/ECcert.bin -inform DER -noout -text
# openssl x509 -pubkey -noout -in /tmp/ECcert.bin  -inform DER 
```

Copy the public key to the host you want to transfer they key *from*.  This is the `encrypting_public_key`

Just to note, you don't *really* need access to a real, permanent TPM on the system you're transferring from.  You can even use a simulator (`--tpm-path="simulator"`)

The following encrypts some data using just the remote `ekpub`

- **encrypt/decrypt**

The following uses a local software TPM to generate and encrypt the transfer key but you can just as easily use a simulator instead `--tpm-path="simulator"`.  To decrypt you would need to specify a TPM (swtpm or real)

```bash
# encrypt
go-tpm-wrapping --mode=import  --aad=myaad \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json 
```

- copy scp `/tmp/encrypted.json` to VM

```bash
# decrypt
go-tpm-wrapping --mode=import  --decrypt --encrypting_public_key=/tmp/ekpubB.pem  \
    --encryptedBlob=/tmp/encrypted.json --aad=myaad \
    --tpm-path="127.0.0.1:2341" 
```

- **With passphrase**

```bash
# encrypt
$ go-tpm-wrapping --mode=import --aad=myaad  \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo --keyPass=bar --encryptedBlob=/tmp/encrypted.json 
```

Then on a machine with the TPM, run

```bash
# decrypt
$ go-tpm-wrapping --mode=import  --decrypt --aad=myaad \
    --encryptedBlob=/tmp/encrypted.json --encrypting_public_key=/tmp/ekpubB.pem --keyPass=bar \
    --tpm-path="127.0.0.1:2341" 
```

- **With PCR**

```bash
## encrypt/decrypt and bind the data to the **destination TPM's** values in
### If you want the TPM where you want to decrypt to have the following PCR values
export TPM2TOOLS_TCTI="swtpm:port=2341"
$ tpm2_pcrread sha256:0,23
  sha256:
    0 : 0x0000000000000000000000000000000000000000000000000000000000000000
    23: 0x0000000000000000000000000000000000000000000000000000000000000000

## then just specify them while encrypting
$ go-tpm-wrapping --mode=import   \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo  \
   --pcrValues=0:0000000000000000000000000000000000000000000000000000000000000000,23:0000000000000000000000000000000000000000000000000000000000000000 \
   --encryptedBlob=/tmp/encrypted.json 
```

then,

```bash
# decrypt
## then these PCRs are read in to decrypt on the destination
$ go-tpm-wrapping --mode=import  --decrypt  \
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

As with seal, you can mandate the PCR values you expect to see (eg if you uspecify an invalid pcr value during decrypt, you'll see an error):

```bash
$ go-tpm-wrapping --mode=import  --decrypt  \
   --dataToEncrypt=foo --encrypting_public_key=/tmp/ekpubB.pem --encryptedBlob=/tmp/encrypted.json \
   --pcrValues=0:0000000000000000000000000000000000000000000000000000000000000000,23:F0A00000000000000000000000000000000000000000000000000000000000DD \   
   --tpm-path="127.0.0.1:2341"

 Error decrypting executing PolicyPCR: TPM_RC_VALUE (parameter 1): value is out of range or is not correct for the context
```

If the local or remote TPM has a passphrase for the Owner or Endorsement key, you can specify  the `--hierarchyPass=` parameter:

```bash
## if the remote has a passphrase on the endorsement key
export TPM2TOOLS_TCTI="swtpm:port=2341"
tpm2_changeauth -c endorsement newpass2

# encrypt and specify the local 
go-tpm-wrapping --mode=import   \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json 

# decrypt and specify the remote
go-tpm-wrapping --mode=import --hierarchyPass=newpass2 --decrypt --encrypting_public_key=/tmp/ekpubB.pem  \
    --encryptedBlob=/tmp/encrypted.json \
    --tpm-path="127.0.0.1:2341" 
```

>> note that during decryption/import, you can omit `--encrypting_public_key=` parameter. Doing so will use the ekPublic key embedded in the proto itself.   If you specify the parameter during decryption, the value is compared to what is in the proto and will fail if different (which means the key to encrypt isn't the same one as you specified in the cli)

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

	_, err := wrapping.SetConfig(ctx, WithTPM(*tpmPath))

	aad := []byte("myaad")
	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt), wrapping.WithAad(aad))

	fmt.Printf("Encrypted: %s\n", hex.EncodeToString(blobInfo.Ciphertext))
```

Decrypt:

```golang
	wrapper := tpmwrap.NewWrapper()

	_, err := wrapping.SetConfig(ctx, WithTPM(*tpmPath))

	b, err := os.ReadFile(*encryptedBlob)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)

	aad := []byte("myaad")
	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo, wrapping.WithAad(aad))

	fmt.Printf("Decrypted %s\n", string(plaintext))
```

```bash
# no auth
## encrypt/decrypt
go run seal_encrypt/main.go --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
  --tpm-path="127.0.0.1:2341"

go run seal_decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
  --tpm-path="127.0.0.1:2341"

# with password
go run seal_encrypt/main.go --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --userAuth=abc \
    --tpm-path="127.0.0.1:2341"

go run seal_decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
   --userAuth=abc  \
    --tpm-path="127.0.0.1:2341"
```


#### Import

API usage for import on the local machine is (the one where you want to transfer a secret *from*)

```golang
import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	tpmwrap "github.com/salrashid123/go-tpm-wrapping"
)

	wrapper := tpmwrap.NewRemoteWrapper()

	_, err = wrapper.SetConfig(ctx, WithEncryptingPublicKey(hex.EncodeToString(b)))

	aad := []byte("myaad")
	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt), wrapping.WithAad(aad))

	eb, err := protojson.Marshal(blobInfo)

	fmt.Printf("Encrypted: %s\n", hex.EncodeToString(blobInfo.Ciphertext))
```

At this point, copy `encrypted_blob` to the machine where you want to transfer a key *to*

```golang
	wrapper := tpmwrap.NewRemoteWrapper()

	_, err = wrapper.SetConfig(ctx, WithTPMPath(*tpmPath), WithEncryptingPublicKey(hex.EncodeToString(b)))

	eb, err := os.ReadFile(*encryptedBlob)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(eb, newBlobInfo)

	aad := []byte("myaad")
	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo, wrapping.WithAad(aad))

	fmt.Printf("Decrypted %s\n", string(plaintext))

```

```bash
# no auth
go run import_encrypt/main.go --dataToEncrypt=foo \
   --encryptedBlob=/tmp/encrypted.json --encrypting_public_key=/tmp/ekpubB.pem 

go run import_decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
   --encrypting_public_key=/tmp/ekpubB.pem --tpm-path="127.0.0.1:2341"

# password 
go run import_encrypt/main.go --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --userAuth=abc 

go run import_decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --userAuth=abc \
   --tpm-path="127.0.0.1:2341"

# pcr 
go run import_encrypt/main.go --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --pcrValues=23:0000000000000000000000000000000000000000000000000000000000000000 

go run import_decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --pcrValues=23:0000000000000000000000000000000000000000000000000000000000000000  \
   --tpm-path="127.0.0.1:2341"   
```

## Options

### Client Data

You can also embed additional arbitrary JSON data into the protobuf as `client_data` structure.  This data is **not** included in the encryption and is not directly related to the `AdditionalData (AAD)` associated with aes-gcm.

The client data field is instead just unencrypted/unverified data you can associate with the encoded key.  

However, you can canonicalize the `client_data` as JSON, hash that and use that hash value as the AAD.  In effect, the client_data can then be used as part of the integrity calculation.

For example, if the client data is

```json
	"clientData": {
		"location": {
			"region": "us",
			"zone": "central"
		},
		"provider": "pqc"
	}
```

then you can encrypt/decrypt as:

- `seal`

```bash
## as cli
go-tpm-wrapping  --mode=seal --aad=myaad  \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
   --clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
   --tpm-path="127.0.0.1:2341"

go-tpm-wrapping  --mode=seal --aad=myaad  --decrypt \
   --clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
   --encryptedBlob=/tmp/encrypted.json --tpm-path="127.0.0.1:2341"

## as library
### note the library example encodes the clientData hash value as the AAD
cd example/
go run client_data_seal/encrypt/main.go --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json \
  --clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
  --tpm-path="127.0.0.1:2341"

go run client_data_seal/decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
  --clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
  --tpm-path="127.0.0.1:2341"
```

- `import`

```bash
tpm2_createek -c /tmp/primaryB.ctx -G rsa -u /tmp/ekB.pub -Q
tpm2_readpublic -c /tmp/primaryB.ctx -o /tmp/ekpubB.pem -f PEM
tpm2_flushcontext -t

## as cli
go-tpm-wrapping  --mode=import  --aad=myaad \
   --encrypting_public_key=/tmp/ekpubB.pem \
   --clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
   --dataToEncrypt=foo --encryptedBlob=/tmp/encrypted.json  

go-tpm-wrapping   --mode=import  --decrypt --encrypting_public_key=/tmp/ekpubB.pem  \
    --encryptedBlob=/tmp/encrypted.json --aad=myaad \
    --clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
    --tpm-path="127.0.0.1:2341" 

## as library
### note the library example encodes the clientData hash value as the AAD
cd example/
go run client_data_import/encrypt/main.go --dataToEncrypt=foo \
   --clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
   --encryptedBlob=/tmp/encrypted.json --encrypting_public_key=/tmp/ekpubB.pem

go run client_data_import/decrypt/main.go --encryptedBlob=/tmp/encrypted.json \
   --clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
   --encrypting_public_key=/tmp/ekpubB.pem --tpm-path="127.0.0.1:2341"    
```

Note that you can specify the client data either in the overall wrapper config or during each encrypt/decrypt method.  If specified in the encrypt/decrypt methods, it takes priority.

specified in config:

```golang
	_, err = wrapper.SetConfig(ctx, tpmwrap.WithPublicKey(string(pubPEMBytes)),
		tpmwrap.WithClientData(*clientData))
```

in operation:

```golang
plaintext, err := wrapper.Decrypt(ctx, newBlobInfo, tpmwrap.WithClientData(*expectedClientData))
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

### Wrapped Key format

#### Seal Key Format

There are two levels of encryption involved with this library and is best described in this flow:

-  Encrypt

1. Create an `AES256-GCM` wrapping key

   ```golang
   key := make([]byte, 32)
   ```

2. Create new *direct* aead wrapper using `wrapaead "github.com/hashicorp/go-kms-wrapping/v2/aead"` and set  `key` as the key. `wrapaead` already includes the [iv into the ciphertext](https://github.com/hashicorp/go-kms-wrapping/blob/main/aead/aead.go#L242-L249) 

   ```golang
	w := wrapaead.NewWrapper()
	err := w.SetAesGcmKeyBytes(key)
	cipherText, _ := w.Encrypt(ctx, plaintext, opt...)
   ```

* `ciphertext`: the encrypted data wrapped using `key` which includes the initialization vector
* `wrappedKey`: the TPM PEM "object" which has the `key` sealed inside it

```json
{
  "ciphertext": "VtV3UmoyD0UjoFwb+RJckvO0SHG72KCDTwUtHEyq5g==",
  "keyInfo": {
    "keyId": "key1",
    "wrappedKey": "eyJuYW1lIjoia2V5MSIsInZlcnNpb24iOjMsInNlYWxlZE9wIjp7ImtleWZpbGUiOiItLS0tLUJFR0lOIFRTUzIgUFJJVkFURSBLRVktLS0tLVxuTUlJQkVBWUdaNEVGQ2dFRG9BTUJBZitrQmd3RWEyVjVNUUlFUUFBQUFRUlFBRTRBQ0FBTEFBQUFFZ0FnNGJyR1xuT0grcGozWkpoVkszNER0cTZidE9FWEZUVEZudXJzRDB6SXZFTitZQUVBQWdnanZzNURzVTRFdURCRlU0dkIyWlxua1l2RjY1MDhaUFFNSnZqSE92VzBnRVVFZ2FBQW5nQWdsVkdwb28vdnoyYlBFSEoyLy9uTERnVWZ5QWZ6Z3ExN1xuaXpXVEZ6V3dZdDhBRUN4UW5TY0lUelJ1UUF2UDhQWndCZ21ablk4c0grN2hRYUpZR2VaY2tLVTZSOGR5YVJCOFxuQllVeVlPc1dEcnJyNUFZN2lSM3d3WjVNcjQ3YTlVekNUUjBpZWtkaFRkTTZscVlyRTlGK0hvZTBpRmJ6TGdVT1xua2lMbnFvdzVaZGs5Y29yeTFsVjJJVEN6ckZTeXd2Q013NTU5c1Z0Q094bkRNb210XG4tLS0tLUVORCBUU1MyIFBSSVZBVEUgS0VZLS0tLS1cbiJ9fQ=="
  }
}
```

If you base64decode the `wrappedKey`

* `keyfile` is the PEM encoded private key which has sealed the `key`

The keyfile is:

```json
{
  "name": "key1",
  "version": 3,
  "sealedOp": {
    "keyfile": "-----BEGIN TSS2 PRIVATE KEY-----\nMIIBEAYGZ4EFCgEDoAMBAf+kBgwEa2V5MQIEQAAAAQRQAE4ACAALAAAAEgAg4brG\nOH+pj3ZJhVK34Dtq6btOEXFTTFnursD0zIvEN+YAEAAggjvs5DsU4EuDBFU4vB2Z\nkYvF6508ZPQMJvjHOvW0gEUEgaAAngAglVGpoo/vz2bPEHJ2//nLDgUfyAfzgq17\nizWTFzWwYt8AECxQnScITzRuQAvP8PZwBgmZnY8sH+7hQaJYGeZckKU6R8dyaRB8\nBYUyYOsWDrrr5AY7iR3wwZ5Mr47a9UzCTR0iekdhTdM6lqYrE9F+Hoe0iFbzLgUO\nkiLnqow5Zdk9cory1lV2ITCzrFSywvCMw559sVtCOxnDMomt\n-----END TSS2 PRIVATE KEY-----\n"
  }
}
```

- Decrypt

1. First load the `keyfile` and unseal:

   ```golang
   key, err := tpm2.Unseal(keyfile)
   ```

2. Create new *direct* aead wrapper using `wrapaead "github.com/hashicorp/go-kms-wrapping/v2/aead"` and set  `key` as the decryption key.

   ```golang
	w := wrapaead.NewWrapper()
	err := w.SetAesGcmKeyBytes(key)
	plainText, _ := w.Decrypt(ctx, cipherText, opt...)
   ```

#### Import Key Format

1. Create an `AES256-GCM` wrapping key

   ```golang
   key := make([]byte, 32)
   ```

2. Create new *direct* aead wrapper using `wrapaead "github.com/hashicorp/go-kms-wrapping/v2/aead"` and set  `key` as the encryption key. `wrapaead` already includes the [iv into the ciphertext](https://github.com/hashicorp/go-kms-wrapping/blob/main/aead/aead.go#L242-L249) 

   ```golang
	w := wrapaead.NewWrapper()
	err := w.SetAesGcmKeyBytes(key)
	cipherText, _ := w.Encrypt(ctx, plaintext, opt...)
   ```

   then create a key to duplicate and set the key as the sensitive

   ```golang
   duplicatingKey = tpm2.TPMTPublic{Type: tpm2.TPMAlgKeyedHash}, tpm2.TPMTSensitive{tpm2.TPM2BSensitiveData{Buffer: key}}
	wrappedKey, _ := tpm2.Duplicate(duplicatingKey)
   ```

* `ciphertext`: the encrypted data wrapped using `key` which includes the initialization vector 
* `wrappedKey`: the TPM PEM "object" which has the `key` sealed inside it

```json
{
  "ciphertext": "/1WtoYdYz7X+eXyHyeqZ6Y6LhSsK/0fuLnXBXzXLIQ==",
  "keyInfo": {
    "mechanism": "1",
    "keyId": "key1",
    "wrappedKey": "eyJuYW1lIjoia2V5MSIsInZlcnNpb24iOjMsInR5cGUiOiJEVVBMSUNBVEUiLCJkdXBsaWNhdGVkT3AiOnsibmFtZSI6ImtleTEiLCJrZXlmaWxlIjoiLS0tLS1CRUdJTiBUU1MyIFBSSVZBVEUgS0VZLS0tLS1cbk1JSUNlQVlHWjRFRkNnRUVvQU1CQWYraGdaWXdnWk13Q3FBRUFnSUJhNkVDQkFBd01hQUVBZ0lCaUtFcEJDY0FcbkFBQWlBQXQ3OGVjb1NWWUlJMHNsU1I4VThaZUNzK0RiZ1lIdGV4aFprV1Y3eTlrTjJRQXdVcUFFQWdJQmNhRktcbkJFZ0FBQUFDQUNDUHpTRnBxNUpwVGd4alB4cTNjb1FyZ2tHN3dnS0ltQi9IckI3ZHdmM2JEZ0FnaU9jcStFZGlcbnN2WHJhK1RGYjllc1pLeUtrMXZZSk12VmU4QXhaaW5GQkUraWdnRUdCSUlCQWdFQXAwSngyTHFVczFjbnRHWXdcbjc5RTBVM0hGMFZGaGxpZE9WSXpqZDR0VmVKUzRjc3gzT25GQURXYll2WVRCMHRuNVFDZjRPMU02NTltZjJjWDhcbjhQd0lxTWJLOWpNNS9weGFaOHRFVGV5RW52VFRTMElNcmpEd2JmV0dTN3AvMHNKVTZsWlA4RDBWbnkrQjdPaTVcbjlhNGxpK2NNMzJRa2dOcjFRQjhOUi91Z0kra2plNm0wTEFrcCs4Yk1vbUVKY21CSUg0RURlYUpDVURSODF3K3hcbndmcll5QXVKV3AzM2R1cFF2NlFrK0t4cndGcitKRTR1VU5vT1pJVHE0YXE2Kzc1UDV6YXVxbjlJVi85SzFRL1dcbm1jNHpIS2o1MzdRNVhES01URTFZRkFTYUdTc25kOTZXL3NWV243L1VDZjNRVW5mWTZuak1NVmdhR0dMMlNJV0RcblNrMW5BQUlFUUFBQlFBUlFBRTRBQ0FBTEFBQUFBQUFnbENVSXNKOUV6ZW1SQmw3aC93RHpxTlExc0V6MzNuSU9cbnRSOHFmeHJaNDk0QUVBQWcwQlA1STlyaWpJeTl5aEFGODFMbmsxTk94SmtQUkV5a0Y1ZXB1Rkp2Tk53RWJnQnNcbkFDQzlXZGhka3I5YS84ZEhJOWRpaWhUZGN2QVVDUzUrRUFCRENLUExWQmIyUWwwSzBIMUV5cEg4SGxSc0NCYlVcbjcrcUpna1doUXlRT0hGaStMTnd5a3NBUm43WnREV1R6QU1jZnE3Yi95RDBSSnZQYlYvZkhpWkZLbEVtZ2NWdTNcblE1T1hlaFBheWtwUVJTS2Zcbi0tLS0tRU5EIFRTUzIgUFJJVkFURSBLRVktLS0tLVxuIiwicGFyZW50TmFtZSI6IjAwMGI3YmYxZTcyODQ5NTYwODIzNGIyNTQ5MWYxNGYxOTc4MmIzZTBkYjgxODFlZDdiMTg1OTkxNjU3YmNiZDkwZGQ5IiwiZWtwdWIiOiJNbVF5WkRKa01tUXlaRFF5TkRVME56UTVOR1V5TURVd05UVTBNalJqTkRrME16SXdOR0kwTlRVNU1tUXlaREprTW1ReVpEQmhOR1EwT1RRNU5ESTBPVFpoTkRFMFpUUXlOamMyWWpjeE5qZzJZalk1TkRjek9UYzNNekEwTWpReE5URTBOVFEyTkRFME1UUm1ORE0wTVRVeE16ZzBNVFJrTkRrME9UUXlORE0yTnpSaU5ETTBNVFV4TkRVME1UYzNOek0xTmpRM05UUXpPVE00TmpJMk9EUm1OMkUzTWpRMk5EY3pOelE1TnpVMFpUUXpOekV3WVRZMk5UZzFNVFpsTlRRM05EUmhOVGswT0RRM05UQTBOVE14TXpBek9ETTVNek15WWpRME1tWXpOVGN4TmpRM056UTRObU0yWVRjd05ETTBNelkxTmpFMllUUXlOVGcwT0RSaU5tTTBPRFU0Tm1JMU9EWmpOR0kxTURRME5EVTNOalV4TjJFeVpqUTNObU0xTlRZME5UUTNNVGN5TlRFMU5qWm1ObVEzT1RjM01HRTNOak01TXpFM05UVmhOVE0yTmpaaE5XRTBaVFk0TnpFM016WTNOakl6TXpKbU5qWTJZelV5TmprMk56VXhOemcxTlRZMk56QTJaRGMxTXpjME9EVXlOekEyWmpZNU5ESTBaVE01TXpRek1UVTRORGcwWXpNd05UVTBOak0xTkRrME1UWm1ORE0xTWpWaE5UYzBNVGN6TnprM056WmpORGsyT0RVNU56UTJOREJoTXpBMU1EVTFORFEyWWpWaE16WTBNak0yTmpRM056WXlOR1V6TURRMk16QTBZVFkyTlRBek5EUmpOVGcyT0RZME5UUTFNakptTjJFM01qVTFORFkyT0RSbU5ERXpOalppTkRJM01UWTVOalEzT0RZeE5ERTJOamMxTkdNME9UTTFNbUl5WWpZME5EYzNNRFUyTm1Nek5ETTJOR1l6TXpRM05qRTJaRFkzTlRjd1lUWmpOVGt6TlRVMk5HRTJZelpqTnpZMFpEYzNOV0UxTWpKbU56QTJNelF4TkdFMU5UTTBNbVkyTmpVeU16WXpNalV6Tm1FMk9UYzRORGMyWXpVNU5EazNORFJoTXpJMk16UTROekEyTlRVMk16ZzNOamN3TkRZMk1UY3dOVFV6TURSa05XRTJOVFU1TXpZMk9EVTRORGczTVRZMU5qUTFNRFJsTmpNek1UWTVNR0UzWVRNME5HTTBNVGN6TkdVME1qWXpOVEF6TXpNME5tVTNOak01TXprM05qUmxORFkyWlRNMU56STBaalF5TkRJMlpEVTROVGMwTXpjM05UQTBZamM1TmpRME9USm1ObU0xTVRZek5qWXpPVGMwTjJFMU9UWTVObUUwWWpVMU5UZzFORE15TXpjek5qTTVOamt6TVRjME16Y3lZalEyTmpNM056UmtNelkzT0RCaE4yRTFNVFE1TkRRME1UVXhOREUwTWpCaE1tUXlaREprTW1ReVpEUTFOR1UwTkRJd05UQTFOVFF5TkdNME9UUXpNakEwWWpRMU5Ua3laREprTW1ReVpESmtNR0U9In19"
  }
}
```

If you base64decode the `wrappedKey`

* `keyfile` is the PEM encoded private key which has sealed the `key`

The keyfile is:

```json
{
  "name": "key1",
  "version": 3,
  "type": "DUPLICATE",
  "duplicatedOp": {
    "name": "key1",
    "keyfile": "-----BEGIN TSS2 PRIVATE KEY-----\nMIICeAYGZ4EFCgEEoAMBAf+hgZYwgZMwCqAEAgIBa6ECBAAwMaAEAgIBiKEpBCcA\nAAAiAAt78ecoSVYII0slSR8U8ZeCs+DbgYHtexhZkWV7y9kN2QAwUqAEAgIBcaFK\nBEgAAAACACCPzSFpq5JpTgxjPxq3coQrgkG7wgKImB/HrB7dwf3bDgAgiOcq+Edi\nsvXra+TFb9esZKyKk1vYJMvVe8AxZinFBE+iggEGBIIBAgEAp0Jx2LqUs1cntGYw\n79E0U3HF0VFhlidOVIzjd4tVeJS4csx3OnFADWbYvYTB0tn5QCf4O1M659mf2cX8\n8PwIqMbK9jM5/pxaZ8tETeyEnvTTS0IMrjDwbfWGS7p/0sJU6lZP8D0Vny+B7Oi5\n9a4li+cM32QkgNr1QB8NR/ugI+kje6m0LAkp+8bMomEJcmBIH4EDeaJCUDR81w+x\nwfrYyAuJWp33dupQv6Qk+KxrwFr+JE4uUNoOZITq4aq6+75P5zauqn9IV/9K1Q/W\nmc4zHKj537Q5XDKMTE1YFASaGSsnd96W/sVWn7/UCf3QUnfY6njMMVgaGGL2SIWD\nSk1nAAIEQAABQARQAE4ACAALAAAAAAAglCUIsJ9EzemRBl7h/wDzqNQ1sEz33nIO\ntR8qfxrZ494AEAAg0BP5I9rijIy9yhAF81Lnk1NOxJkPREykF5epuFJvNNwEbgBs\nACC9Wdhdkr9a/8dHI9diihTdcvAUCS5+EABDCKPLVBb2Ql0K0H1EypH8HlRsCBbU\n7+qJgkWhQyQOHFi+LNwyksARn7ZtDWTzAMcfq7b/yD0RJvPbV/fHiZFKlEmgcVu3\nQ5OXehPaykpQRSKf\n-----END TSS2 PRIVATE KEY-----\n",
    "parentName": "000b7bf1e728495608234b25491f14f19782b3e0db8181ed7b185991657bcbd90dd9",
    "ekpub": "MmQyZDJkMmQyZDQyNDU0NzQ5NGUyMDUwNTU0MjRjNDk0MzIwNGI0NTU5MmQyZDJkMmQyZDBhNGQ0OTQ5NDI0OTZhNDE0ZTQyNjc2YjcxNjg2YjY5NDczOTc3MzA0MjQxNTE0NTQ2NDE0MTRmNDM0MTUxMzg0MTRkNDk0OTQyNDM2NzRiNDM0MTUxNDU0MTc3NzM1NjQ3NTQzOTM4NjI2ODRmN2E3MjQ2NDczNzQ5NzU0ZTQzNzEwYTY2NTg1MTZlNTQ3NDRhNTk0ODQ3NTA0NTMxMzAzODM5MzMyYjQ0MmYzNTcxNjQ3NzQ4NmM2YTcwNDM0MzY1NjE2YTQyNTg0ODRiNmM0ODU4NmI1ODZjNGI1MDQ0NDU3NjUxN2EyZjQ3NmM1NTY0NTQ3MTcyNTE1NjZmNmQ3OTc3MGE3NjM5MzE3NTVhNTM2NjZhNWE0ZTY4NzE3MzY3NjIzMzJmNjY2YzUyNjk2NzUxNzg1NTY2NzA2ZDc1Mzc0ODUyNzA2ZjY5NDI0ZTM5MzQzMTU4NDg0YzMwNTU0NjM1NDk0MTZmNDM1MjVhNTc0MTczNzk3NzZjNDk2ODU5NzQ2NDBhMzA1MDU1NDQ2YjVhMzY0MjM2NjQ3NzYyNGUzMDQ2MzA0YTY2NTAzNDRjNTg2ODY0NTQ1MjJmN2E3MjU1NDY2ODRmNDEzNjZiNDI3MTY5NjQ3ODYxNDE2Njc1NGM0OTM1MmIyYjY0NDc3MDU2NmMzNDM2NGYzMzQ3NjE2ZDY3NTcwYTZjNTkzNTU2NGE2YzZjNzY0ZDc3NWE1MjJmNzA2MzQxNGE1NTM0MmY2NjUyMzYzMjUzNmE2OTc4NDc2YzU5NDk3NDRhMzI2MzQ4NzA2NTU2Mzg3NjcwNDY2MTcwNTUzMDRkNWE2NTU5MzY2ODU4NDg3MTY1NjQ1MDRlNjMzMTY5MGE3YTM0NGM0MTczNGU0MjYzNTAzMzM0NmU3NjM5Mzk3NjRlNDY2ZTM1NzI0ZjQyNDI2ZDU4NTc0Mzc3NTA0Yjc5NjQ0OTJmNmM1MTYzNjYzOTc0N2E1OTY5NmE0YjU1NTg1NDMyMzczNjM5NjkzMTc0MzcyYjQ2NjM3NzRkMzY3ODBhN2E1MTQ5NDQ0MTUxNDE0MjBhMmQyZDJkMmQyZDQ1NGU0NDIwNTA1NTQyNGM0OTQzMjA0YjQ1NTkyZDJkMmQyZDJkMGE="
  }
}
```

- Decrypt

1. First load the `keyfile` and unseal:

   ```golang
   keyImport, err := tpm2.Import(keyfile)
   keyObject, err := tpm2.Load(keyImport)
   key, err := tpm2.Unseal(keyObject)
   ```

2. Create new *direct* aead wrapper using `wrapaead "github.com/hashicorp/go-kms-wrapping/v2/aead"` and set  `kemSharedSecret` as the key.

   ```golang
	w := wrapaead.NewWrapper()
	err := w.SetAesGcmKeyBytes(key)
	plainText, _ := w.Decrypt(ctx, cipherText, opt...)
   ```

### Versions

The following lists the [Version](https://github.com/salrashid123/go-pqc-wrapping/blob/main/common.go#L31) values used in the encoding of the key.

Its important to decrypt using a cli or library version which is consistent with the proto or key encoding formats.


| KeyVersion | Date |
|------------|-------------|
| 1 | `4/10/24` |
| 2 | `4/14/25` |
| 3 | `1/2/26` |

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

   1. create a new `AES256-GCM` key.
   2. encrypt the plaintext using this key to get a ciphertext
   3. generate a primary object on the TPM of type `TPMAlgKeyedHash` and set its "sensitive" data to _inner encryption key_ (from step 1)
   4. convert the TPM key to a PEM encoded format
   5. create a protobuf that contains the encoded keyfile
   6. return the ciphertext, initialization vector and encoded tpm key

   ```
   aesKey = new AES256GCM()
   ciphertext, iv: = aes.Encrypt(aesKey, plaintext)
   key1 =  TPMAlgKeyedHash( sensitive = aesKey )
   tpm_key = tpm2_seal(key1)
   ```

to `Decrypt`:

   1. read the ciphertext, IV and encoded tpm key
   2. generate a primary key on the TPM
   3. create a session or pcr policy to apply to the TPM 
   4. load the encoded tpm key
   5. unseal the tpm key to acquire the _inner encryption key_ (`aesKey`)
   6. use the inner key, IV and ciphertext to decrypt plaintext

   ```
   aesKey = tpm_key.unseal(tpm_key)
   plaintext1= aes.Decrypt(aesKey, iv, ciphertext) 
   ```

#### `Import`

   For this,  you encrypt some data _remotely_ using just a public encryption key for the target TPM.  YOu do not need a TPM on your laptop but you do need one on the destination (ofcourse)
   
**A**: To transfer a secret from your local laptop to `TPM-B` with **password** or **PCRPolicy**

   1. `TPM-B`: create `ekpubB.pem`
   2.  copy `ekpubB.pem` to `local`

on `laptop`:

   1. create a new `AES256-GCM` key.
   2. encrypt the plaintext using this key to get a ciphertext
   4. construct a TPM Public of type `tpm2.TPMAlgKeyedHash`  with `PolicyOr[PolicyAuthValue|PolicyDuplicateSelect]` or as `PolicyOr[PolicyPCR|PolicyDuplicateSelect]`.
   5. set the `aesKy` as the TPM keys sensitive part (i.,e seal data)
   6. duplicate the key using the `Policyduplicateselect`

   ```text
   aesKey = new AES256GCM()
   ciphertext, iv: = aes.Encrypt(aesKey, plaintext)
   duplicateKey =(auth=PolicyOr[PolicyAuthValue|PolicyDuplicateSelect], type=tpm2.TPMAlgKeyedHash, sensitive=aesKey)
   duplicate = tpm2_duplicate(duplicateKey, ekPubB.pem)
   ```

copy the duplicated key and wrapped ciphertext1, iv1 to `TPM-B`  (all of which is encoded into one file)

on `TPM-B`:

   7. create a real session with `PolicySecret` (since we used the EndorsementKey)
   8. Import and Load the duplicated key with the policy
   9. Use the TPM-based key, specify `PolicyOr[PolicyAuthValue|PolicyDuplicateSelect]` or as `PolicyOr[PolicyPCR|PolicyDuplicateSelect]` to unseal the  _inner encryption key (`aesKey`)

   ```text
   tpm_key = tpm2_import(duplicate)
   aesKey = tpm2_unseal(tpm_key)
   plaintext = aes.Decrypt(aesKey, iv, ciphertext) 
   ```

If you want to see the full flow on how the import function works to transfer a key from A to B:

Note, this utility does not require a TPM on the system where you are transferring _from_ (eg, TPM-B below).  We are only using TPM-B because it is easier to show the flow.

- Initialize

```bash

## Initialize TPM-A
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

## Initialize TPM-B
rm -rf /tmp/myvtpm2 && mkdir /tmp/myvtpm2
swtpm_setup --tpmstate /tmp/myvtpm2 --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear
```

- on `TPM-B`, export `EkPub`

```bash
export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"

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

### then Auth
tpm2_startauthsession -S session.dat
tpm2_policyauthvalue -S session.dat -L policyA_auth.dat 
tpm2_flushcontext session.dat
rm session.dat

## now create a key with policyduplicateselect
tpm2_startauthsession -S session.dat
tpm2_policyduplicationselect -S session.dat  -N dst_n.name -L policyA_dupselect.dat 
tpm2_flushcontext session.dat
rm session.dat

### create an OR policy together
tpm2_startauthsession -S session.dat
tpm2_policyor -S session.dat -L policyA_or.dat sha256:policyA_auth.dat,policyA_dupselect.dat 
tpm2_flushcontext session.dat

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

echo "my sealed data" > seal.dat

tpm2_create -C primary.ctx -i seal.dat -u key.pub -r key.priv  -L policyA_or.dat -p foo -a ""
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_load -C primary.ctx -r key.priv -u key.pub -c key.ctx
tpm2_readpublic -c key.ctx -o dup.pub
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

## now duplicate
tpm2_startauthsession --policy-session -S session.dat
tpm2_readpublic -c key.ctx -n dupkey.name
tpm2_policyduplicationselect -S session.dat  -N dst_n.name -L policyA_dupselect.dat  -n dupkey.name
tpm2_policyor -S session.dat -L policyA_or.dat sha256:policyA_auth.dat,policyA_dupselect.dat 
tpm2_duplicate -C new_parent.ctx -c key.ctx -G null  -p "session:session.dat" -r dup.dup -s dup.seed

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

tpm2_import -C /tmp/primaryB.ctx -u /tmp/dup.pub -i /tmp/dup.dup -r dup.prv \
   -s /tmp/dup.seed --parent-auth session:session.ctx

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement

tpm2_load -C /tmp/primaryB.ctx -c imported_key.ctx -u /tmp/dup.pub -r dup.prv  --auth session:session.ctx
tpm2_print -t TPM2B_PUBLIC /tmp/dup.pub

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_startauthsession --policy-session  -S session.dat
tpm2_policyauthvalue -S session.dat -L policyA_auth.dat 
tpm2_flushcontext session.dat

tpm2_startauthsession --policy-session  -S session.dat
tpm2_policyduplicationselect -S session.dat  -N /tmp/ekpubBname.bin -L policyA_dupselect.dat
tpm2_flushcontext session.dat

tpm2_startauthsession --policy-session -S session.dat
tpm2_policyauthvalue -S session.dat -L policyA_auth.dat 
tpm2_policyor -S session.dat -L policyA_or.dat sha256:policyA_auth.dat,policyA_dupselect.dat 

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

$ protoc -I ./ --include_imports \
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

_TODO_

The default mode for "import" utilizes the Endorsement Public key.  A TODO is to allow _any_ encryption key you trust on the target TPM (`TPM-B`).

You would create an arbitrary encryption-only key using something like the following and evict it to a persistent handle as shown below on `TPM-B`

---

#### Using swtpm

If you want to test locally with software TPMs:

```bash
### start the

## Initialize TPM-B
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && \
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && \
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2

### for TPM-B
export TPM2TOOLS_TCTI="swtpm:port=2341"
```

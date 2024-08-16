module main

go 1.22.0

toolchain go1.22.4

require (
	github.com/google/go-tpm v0.9.2-0.20240812212553-1642fe0ffa2a
	github.com/google/go-tpm-tools v0.4.4
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.16
	github.com/salrashid123/go-tpm-wrapping v0.0.0
	google.golang.org/protobuf v1.34.2
)

require (
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20240725205618-b7c5a84edf9d // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/salrashid123/tpmrand v0.4.0 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
)

replace github.com/salrashid123/go-tpm-wrapping => ../

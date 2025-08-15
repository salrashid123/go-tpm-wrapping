module main

go 1.23.0

toolchain go1.24.0

require (
	github.com/google/go-tpm v0.9.5
	github.com/google/go-tpm-tools v0.4.5
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.18
	github.com/salrashid123/go-tpm-wrapping v1.8.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20250520203025-c3c3a4ec1653 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/salrashid123/tpm2genkey v0.8.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
)

replace github.com/salrashid123/go-tpm-wrapping => ../

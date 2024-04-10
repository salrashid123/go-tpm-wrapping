package tpmwrap

import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
	opts := getDefaultOptions()
	var wrappingOptions []wrapping.Option
	var localOptions []OptionFunc
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case wrapping.OptionFunc:
			wrappingOptions = append(wrappingOptions, o)
		case OptionFunc:
			localOptions = append(localOptions, to)
		}
	}

	// Parse the global options
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "user_agent":
				opts.withUserAgent = v
			case "tpm_path":
				opts.withTPMPath = v
			case "pcrs":
				opts.withPCRS = v
			case "pcr_values":
				opts.withPCRValues = v
			case "encrypting_public_key":
				opts.withEncryptingPublicKey = v
			}
		}
	}

	// Now run the local options functions. This may overwrite options set by
	// the options above.
	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
			}
		}
	}

	return &opts, nil
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options
	withUserAgent           string
	withTPMPath             string
	withPCRS                string
	withPCRValues           string
	withEncryptingPublicKey string
}

func getDefaultOptions() options {
	return options{}
}

// WithUserAgent provides a way to chose the user agent
func WithUserAgent(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withUserAgent = with
			return nil
		})
	}
}

// Path to the TPM device (/dev/tpm0)
func WithTPMPath(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withTPMPath = with
			return nil
		})
	}
}

// List of PCR banks to bind the key against.
// Multiple PCR values are comma separated (.WithPCRS("16,23"))
func WithPCRS(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPCRS = with
			return nil
		})
	}
}

// List of PCR Value
// Multiple PCR values are comma separated (.WithPCRValues("0:123abc,7:abcae"))
func WithPCRValues(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPCRValues = with
			return nil
		})
	}
}

// Encrypted public key
// Multiple PCR values are comma separated (.WithPCRValues("hex_encoded_string"))
func WithEncryptingPublicKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withEncryptingPublicKey = with
			return nil
		})
	}
}

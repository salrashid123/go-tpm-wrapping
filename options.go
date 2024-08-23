package tpmwrap

import (
	"io"

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
			case TPM_PATH:
				opts.withTPMPath = v
			case PCR_VALUES:
				opts.withPCRValues = v
			case USER_AUTH:
				opts.withUserAuth = v
			case HIERARCHY_AUTH:
				opts.withHierarchyAuth = v
			case KEY_NAME:
				opts.withKeyName = v
			case ENCRYPTING_PUBLIC_KEY:
				opts.withEncryptingPublicKey = v
			case SESSION_ENCRYPTION_NAME:
				opts.withSessionEncryptionName = v
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
	withUserAgent             string
	withTPMPath               string
	withTPM                   io.ReadWriteCloser
	withPCRValues             string
	withUserAuth              string
	withHierarchyAuth         string
	withKeyName               string
	withEncryptingPublicKey   string
	withSessionEncryptionName string
	withDebug                 bool
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

// WithUserAuth provides a way to chose the user agent
func WithUserAuth(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withUserAuth = with
			return nil
		})
	}
}

// WithHierarchyAuth provides a way to set the passphrase on the hierarchy (if any)
func WithHierarchyAuth(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withHierarchyAuth = with
			return nil
		})
	}
}

// WithKeyName provides a way to set the passphrase on the hierarchy (if any)
func WithKeyName(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyName = with
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

// An actual TPM readcloser object pointer
func WithTPM(with io.ReadWriteCloser) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withTPM = with
			return nil
		})
	}
}

// List of PCR banks Value
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
func WithEncryptingPublicKey(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withEncryptingPublicKey = with
			return nil
		})
	}
}

// TPM Object "Name" to encrypt the os->TPM session
func WithSessionEncryptionName(with string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withSessionEncryptionName = with
			return nil
		})
	}
}

func WithDebug(with bool) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withDebug = with
			return nil
		})
	}
}

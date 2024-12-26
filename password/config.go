package password

type Options struct {
	Length         int
	IncludeLower   bool
	IncludeUpper   bool
	IncludeNumbers bool
	IncludeSymbols bool
	SymbolRange    string
}

// Option is a functional option for configuring PasswordOptions
type Option func(*Options)

// WithLength sets the length of the password
func WithLength(length int) Option {
	return func(opts *Options) {
		opts.Length = length
	}
}

// WithLowercase enables lowercase characters in the password
func WithLowercase(val bool) Option {
	return func(opts *Options) {
		opts.IncludeLower = val
	}
}

// WithUppercase enables uppercase characters in the password
func WithUppercase(val bool) Option {
	return func(opts *Options) {
		opts.IncludeUpper = val
	}
}

// WithNumbers enables numeric characters in the password
func WithNumbers(val bool) Option {
	return func(opts *Options) {
		opts.IncludeNumbers = val
	}
}

// WithSymbols enables symbols in the password
func WithSymbols(val bool, symbolRange ...string) Option {
	return func(opts *Options) {
		opts.IncludeSymbols = val
		if len(symbolRange) > 0 {
			opts.SymbolRange = symbolRange[0]
		}
	}
}

var defaultOptions = Options{
	Length:         16,                            // default length
	SymbolRange:    "!@#$%^&*()_-+={[}]|:;<,>.?/", // default symbol range
	IncludeLower:   true,
	IncludeUpper:   true,
	IncludeSymbols: true,
	IncludeNumbers: true,
}

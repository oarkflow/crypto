package password

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
)

var defaultGenerator *Generator

var passwordBufferPool = sync.Pool{
	New: func() interface{} {
		// Initialize with a buffer of a maximum expected size (this can be tuned)
		return make([]byte, 0, 128)
	},
}

func init() {
	defaultGenerator, _ = NewGenerator()
}

type Generator struct {
	opts Options
	pool string
}

func (g *Generator) Generate() (string, error) {
	password := passwordBufferPool.Get().([]byte)
	clear(password)
	if cap(password) < g.opts.Length {
		password = make([]byte, g.opts.Length)
	} else {
		password = password[:g.opts.Length]
	}
	poolLen := int64(len(g.pool))
	for i := 0; i < g.opts.Length; i++ {
		index, err := rand.Int(rand.Reader, big.NewInt(poolLen))
		if err != nil {
			passwordBufferPool.Put(password)
			return "", fmt.Errorf("failed to generate random index: %v", err)
		}
		password[i] = g.pool[index.Int64()]
	}
	defer passwordBufferPool.Put(password)
	return string(password), nil
}

func (g *Generator) Validate(password string) error {
	var hasLower, hasUpper, hasNumber, hasSymbol bool
	for _, char := range password {
		if g.opts.IncludeLower && !hasLower && 'a' <= char && char <= 'z' {
			hasLower = true
		}
		if g.opts.IncludeUpper && !hasUpper && 'A' <= char && char <= 'Z' {
			hasUpper = true
		}
		if g.opts.IncludeNumbers && !hasNumber && '0' <= char && char <= '9' {
			hasNumber = true
		}
		if g.opts.IncludeSymbols && !hasSymbol && strings.ContainsRune(g.opts.SymbolRange, char) {
			hasSymbol = true
		}
	}
	if g.opts.IncludeLower && !hasLower {
		return errors.New("password does not include a lowercase character")
	}
	if g.opts.IncludeUpper && !hasUpper {
		return errors.New("password does not include an uppercase character")
	}
	if g.opts.IncludeNumbers && !hasNumber {
		return errors.New("password does not include a numeric character")
	}
	if g.opts.IncludeSymbols && !hasSymbol {
		return errors.New("password does not include a symbol")
	}
	return nil
}

func NewGenerator(opt ...Option) (*Generator, error) {
	options := defaultOptions
	for _, op := range opt {
		op(&options)
	}
	if options.Length < 8 {
		return nil, errors.New("password length must be at least 8 characters")
	}
	var characterPool strings.Builder
	if options.IncludeLower {
		characterPool.WriteString("abcdefghijklmnopqrstuvwxyz")
	}
	if options.IncludeUpper {
		characterPool.WriteString("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
	if options.IncludeNumbers {
		characterPool.WriteString("0123456789")
	}
	if options.IncludeSymbols {
		characterPool.WriteString(options.SymbolRange)
	}
	pool := characterPool.String()
	if len(pool) == 0 {
		return nil, errors.New("character pool is empty; enable at least one character type")
	}
	return &Generator{
		opts: options,
		pool: pool,
	}, nil
}

func DefaultGenerator(opt ...Option) (*Generator, error) {
	var err error
	defaultGenerator, err = NewGenerator(opt...)
	return defaultGenerator, err
}

func Generate(opt ...Option) (string, error) {
	if len(opt) > 0 {
		generator, err := NewGenerator(opt...)
		if err != nil {
			return "", err
		}
		return generator.Generate()
	}
	return defaultGenerator.Generate()
}

func Validate(password string, opt ...Option) error {
	if len(opt) > 0 {
		generator, err := NewGenerator(opt...)
		if err != nil {
			return err
		}
		return generator.Validate(password)
	}
	return defaultGenerator.Validate(password)
}

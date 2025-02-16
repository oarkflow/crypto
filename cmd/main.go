package main

import (
	"os"
	"strconv"

	"github.com/oarkflow/cli"
	"github.com/oarkflow/cli/contracts"

	"github.com/oarkflow/crypto"
)

func main() {
	app := cli.New()
	client := app.Instance.Client()
	client.Register([]contracts.Command{
		NewListCommand(client),
		GenCACommand{},
		GenServerCommand{},
		GenClientCommand{},
		GenCodeSignCommand{},
		GenCRLCommand{},
		SignCommand{},
		VerifyCommand{},
		SignTextCommand{},
		VerifyTextCommand{},
		SignJSONCommand{},
		VerifyJSONCommand{},
		InspectCommand{},
		ValidateCommand{},
	})
	app.Instance.Client().Run(os.Args, true)
}

func NewListCommand(app contracts.Cli) *ListCommand {
	return &ListCommand{app: app}
}

type ListCommand struct {
	app contracts.Cli
}

// Signature The name and signature of the console command.
func (receiver *ListCommand) Signature() string {
	return "list"
}

// Description The console command description.
func (receiver *ListCommand) Description() string {
	return "List commands"
}

// Extend The console command extend.
func (receiver *ListCommand) Extend() contracts.Extend {
	return contracts.Extend{}
}

// Handle Execute the console command.
func (receiver *ListCommand) Handle(ctx contracts.Context) error {
	receiver.app.Call("--help")

	return nil
}

// GenCACommand implements the "gen-ca" command.
type GenCACommand struct{}

func (cmd GenCACommand) Signature() string {
	return "gen-ca"
}

func (cmd GenCACommand) Description() string {
	return "Generate a CA certificate and private key"
}

func (cmd GenCACommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Certificate Generation",
		Flags: []contracts.Flag{
			{Name: "organization", Usage: "Organization Name", Value: "My Company"},
			{Name: "country", Usage: "Country Name (NP, US, etc)", Value: "NP"},
			{Name: "curve", Usage: "ECDSA curve (P224, P256, P384, P521)", Value: "P384"},
			{Name: "cn", Usage: "Common Name", Value: "My Secure CA"},
			{Name: "cert", Usage: "Output certificate file", Value: "ca.crt"},
			{Name: "key", Usage: "Output private key file", Value: "ca.key"},
		},
	}
}

func (cmd GenCACommand) Handle(ctx contracts.Context) error {
	params := crypto.CAParams{
		OrganizationName: ctx.Option("organization"),
		Country:          ctx.Option("country"),
		Curve:            ctx.Option("curve"),
		CommonName:       ctx.Option("cn"),
		CertOut:          ctx.Option("cert"),
		KeyOut:           ctx.Option("key"),
	}
	crypto.GenerateCAWithParams(params)
	return nil
}

// GenServerCommand implements the "gen-server" command.
type GenServerCommand struct{}

func (cmd GenServerCommand) Signature() string {
	return "gen-server"
}

func (cmd GenServerCommand) Description() string {
	return "Generate a server certificate signed by a CA"
}

func (cmd GenServerCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Certificate Generation",
		Flags: []contracts.Flag{
			{Name: "ca", Usage: "CA certificate file", Value: "ca.crt"},
			{Name: "cakey", Usage: "CA private key file", Value: "ca.key"},
			{Name: "key-type", Usage: "Key type (ECDSA or RSA)", Value: "ECDSA"},
			{Name: "param", Usage: "Curve name (for ECDSA) or RSA bits (e.g., 2048)", Value: "P256"},
			{Name: "cn", Usage: "Common Name", Value: "server.example.com"},
			{Name: "dns", Usage: "Comma-separated DNS names", Value: "localhost,server.example.com"},
			{Name: "ip", Usage: "Comma-separated IP addresses", Value: "127.0.0.1"},
			{Name: "cert", Usage: "Output certificate file", Value: "server.crt"},
			{Name: "key", Usage: "Output private key file", Value: "server.key"},
		},
	}
}

func (cmd GenServerCommand) Handle(ctx contracts.Context) error {
	params := crypto.ServerParams{
		CACertFile: ctx.Option("ca"),
		CAKeyFile:  ctx.Option("cakey"),
		KeyType:    ctx.Option("key-type"),
		Param:      ctx.Option("param"),
		CommonName: ctx.Option("cn"),
		DNSNames:   ctx.Option("dns"),
		IPList:     ctx.Option("ip"),
		CertOut:    ctx.Option("cert"),
		KeyOut:     ctx.Option("key"),
	}
	crypto.GenerateServerWithParams(params)
	return nil
}

// GenClientCommand implements the "gen-client" command.
type GenClientCommand struct{}

func (cmd GenClientCommand) Signature() string {
	return "gen-client"
}

func (cmd GenClientCommand) Description() string {
	return "Generate a client certificate signed by a CA"
}

func (cmd GenClientCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Certificate Generation",
		Flags: []contracts.Flag{
			{Name: "ca", Usage: "CA certificate file", Value: "ca.crt"},
			{Name: "cakey", Usage: "CA private key file", Value: "ca.key"},
			{Name: "cn", Usage: "Common Name", Value: "client-user"},
			{Name: "cert", Usage: "Output certificate file", Value: "client.crt"},
			{Name: "key", Usage: "Output private key file", Value: "client.key"},
		},
	}
}

func (cmd GenClientCommand) Handle(ctx contracts.Context) error {
	params := crypto.ClientParams{
		CACertFile: ctx.Option("ca"),
		CAKeyFile:  ctx.Option("cakey"),
		CommonName: ctx.Option("cn"),
		CertOut:    ctx.Option("cert"),
		KeyOut:     ctx.Option("key"),
	}
	crypto.GenerateClientWithParams(params)
	return nil
}

// GenCodeSignCommand implements the "gen-code-sign" command.
type GenCodeSignCommand struct{}

func (cmd GenCodeSignCommand) Signature() string {
	return "gen-code-sign"
}

func (cmd GenCodeSignCommand) Description() string {
	return "Generate a code-signing certificate signed by a CA"
}

func (cmd GenCodeSignCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Certificate Generation",
		Flags: []contracts.Flag{
			{Name: "ca", Usage: "CA certificate file", Value: "ca.crt"},
			{Name: "cakey", Usage: "CA private key file", Value: "ca.key"},
			{Name: "cn", Usage: "Common Name", Value: "file-signer"},
			{Name: "rsa-bits", Usage: "RSA key size in bits", Value: "2048"},
			{Name: "cert", Usage: "Output certificate file", Value: "code_sign.crt"},
			{Name: "key", Usage: "Output private key file", Value: "code_sign.key"},
		},
	}
}

func (cmd GenCodeSignCommand) Handle(ctx contracts.Context) error {
	rsaBits, err := strconv.Atoi(ctx.Option("rsa-bits"))
	if err != nil {
		return err
	}
	params := crypto.CodeSignParams{
		CACertFile: ctx.Option("ca"),
		CAKeyFile:  ctx.Option("cakey"),
		CommonName: ctx.Option("cn"),
		RsaBits:    rsaBits,
		CertOut:    ctx.Option("cert"),
		KeyOut:     ctx.Option("key"),
	}
	crypto.GenerateCodeSignWithParams(params)
	return nil
}

// GenCRLCommand implements the "gen-crl" command.
type GenCRLCommand struct{}

func (cmd GenCRLCommand) Signature() string {
	return "gen-crl"
}

func (cmd GenCRLCommand) Description() string {
	return "Generate a Certificate Revocation List (CRL)"
}

func (cmd GenCRLCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "CRL",
		Flags: []contracts.Flag{
			{Name: "ca", Usage: "CA certificate file", Value: "ca.crt"},
			{Name: "cakey", Usage: "CA private key file", Value: "ca.key"},
			{Name: "revoked", Usage: "Comma-separated revoked certificate serial numbers", Value: ""},
			{Name: "crl", Usage: "Output CRL file", Value: "ca.crl"},
		},
	}
}

func (cmd GenCRLCommand) Handle(ctx contracts.Context) error {
	params := crypto.CRLParams{
		CACertFile: ctx.Option("ca"),
		CAKeyFile:  ctx.Option("cakey"),
		Revoked:    ctx.Option("revoked"),
		CRLOut:     ctx.Option("crl"),
	}
	crypto.GenerateCRLWithParams(params)
	return nil
}

// SignCommand implements the "sign" command.
type SignCommand struct{}

func (cmd SignCommand) Signature() string {
	return "sign"
}

func (cmd SignCommand) Description() string {
	return "Sign a file using a private key"
}

func (cmd SignCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Signing",
		Flags: []contracts.Flag{
			{Name: "file", Usage: "File to sign", Value: ""},
			{Name: "key", Usage: "Private key file", Value: ""},
			{Name: "out", Usage: "Output signature file (default: <file>.sig)", Value: ""},
		},
	}
}

func (cmd SignCommand) Handle(ctx contracts.Context) error {
	params := crypto.SignParams{
		FileToSign: ctx.Option("file"),
		KeyFile:    ctx.Option("key"),
		OutSig:     ctx.Option("out"),
	}
	crypto.SignFileWithParams(params)
	return nil
}

// VerifyCommand implements the "verify" command.
type VerifyCommand struct{}

func (cmd VerifyCommand) Signature() string {
	return "verify"
}

func (cmd VerifyCommand) Description() string {
	return "Verify a file’s signature using a certificate"
}

func (cmd VerifyCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Signing",
		Flags: []contracts.Flag{
			{Name: "file", Usage: "File to verify", Value: ""},
			{Name: "sig", Usage: "Signature file", Value: ""},
			{Name: "cert", Usage: "Certificate file containing public key", Value: ""},
		},
	}
}

func (cmd VerifyCommand) Handle(ctx contracts.Context) error {
	params := crypto.VerifyParams{
		FileToVerify: ctx.Option("file"),
		SigFile:      ctx.Option("sig"),
		CertFile:     ctx.Option("cert"),
	}
	crypto.VerifyFileSignatureWithParams(params)
	return nil
}

// SignTextCommand implements the "sign-text" command.
type SignTextCommand struct{}

func (cmd SignTextCommand) Signature() string {
	return "sign-text"
}

func (cmd SignTextCommand) Description() string {
	return "Sign plain text using a private key"
}

func (cmd SignTextCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Signing",
		Flags: []contracts.Flag{
			{Name: "key", Usage: "Private key file", Value: ""},
			{Name: "text", Usage: "Text to sign", Value: ""},
			{Name: "out", Usage: "Output signature file (base64 encoded)", Value: ""},
		},
	}
}

func (cmd SignTextCommand) Handle(ctx contracts.Context) error {
	params := crypto.SignTextParams{
		KeyFile: ctx.Option("key"),
		Text:    ctx.Option("text"),
		OutSig:  ctx.Option("out"),
	}
	crypto.SignTextWithParams(params)
	return nil
}

// VerifyTextCommand implements the "verify-text" command.
type VerifyTextCommand struct{}

func (cmd VerifyTextCommand) Signature() string {
	return "verify-text"
}

func (cmd VerifyTextCommand) Description() string {
	return "Verify a plain text signature using a certificate"
}

func (cmd VerifyTextCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Signing",
		Flags: []contracts.Flag{
			{Name: "cert", Usage: "Certificate file containing public key", Value: ""},
			{Name: "text", Usage: "Text to verify", Value: ""},
			{Name: "sig", Usage: "Signature (base64 encoded)", Value: ""},
		},
	}
}

func (cmd VerifyTextCommand) Handle(ctx contracts.Context) error {
	params := crypto.VerifyTextParams{
		CertFile:  ctx.Option("cert"),
		Text:      ctx.Option("text"),
		Signature: ctx.Option("sig"),
	}
	crypto.VerifyTextWithParams(params)
	return nil
}

// SignJSONCommand implements the "sign-json" command.
type SignJSONCommand struct{}

func (cmd SignJSONCommand) Signature() string {
	return "sign-json"
}

func (cmd SignJSONCommand) Description() string {
	return "Sign JSON data using a private key"
}

func (cmd SignJSONCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Signing",
		Flags: []contracts.Flag{
			{Name: "key", Usage: "Private key file", Value: ""},
			{Name: "json", Usage: "JSON string to sign", Value: ""},
			{Name: "out", Usage: "Output signature file (base64 encoded)", Value: ""},
		},
	}
}

func (cmd SignJSONCommand) Handle(ctx contracts.Context) error {
	params := crypto.SignJSONParams{
		KeyFile: ctx.Option("key"),
		JSONStr: ctx.Option("json"),
		OutSig:  ctx.Option("out"),
	}
	crypto.SignJSONWithParams(params)
	return nil
}

// VerifyJSONCommand implements the "verify-json" command.
type VerifyJSONCommand struct{}

func (cmd VerifyJSONCommand) Signature() string {
	return "verify-json"
}

func (cmd VerifyJSONCommand) Description() string {
	return "Verify a JSON signature using a certificate"
}

func (cmd VerifyJSONCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Signing",
		Flags: []contracts.Flag{
			{Name: "cert", Usage: "Certificate file containing public key", Value: ""},
			{Name: "json", Usage: "JSON string to verify", Value: ""},
			{Name: "sig", Usage: "Signature (base64 encoded)", Value: ""},
		},
	}
}

func (cmd VerifyJSONCommand) Handle(ctx contracts.Context) error {
	params := crypto.VerifyJSONParams{
		CertFile:  ctx.Option("cert"),
		JSONStr:   ctx.Option("json"),
		Signature: ctx.Option("sig"),
	}
	crypto.VerifyJSONWithParams(params)
	return nil
}

// InspectCommand implements the "inspect" command.
type InspectCommand struct{}

func (cmd InspectCommand) Signature() string {
	return "inspect"
}

func (cmd InspectCommand) Description() string {
	return "Inspect a certificate"
}

func (cmd InspectCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Certificate",
		Flags: []contracts.Flag{
			{Name: "cert", Usage: "Certificate file to inspect", Value: ""},
		},
	}
}

func (cmd InspectCommand) Handle(ctx contracts.Context) error {
	params := crypto.InspectParams{
		CertFile: ctx.Option("cert"),
	}
	crypto.InspectCertificateWithParams(params)
	return nil
}

// ValidateCommand implements the "validate" command.
type ValidateCommand struct{}

func (cmd ValidateCommand) Signature() string {
	return "validate"
}

func (cmd ValidateCommand) Description() string {
	return "Validate a client certificate against a CA"
}

func (cmd ValidateCommand) Extend() contracts.Extend {
	return contracts.Extend{
		Category: "Certificate",
		Flags: []contracts.Flag{
			{Name: "cert", Usage: "Client certificate file", Value: ""},
			{Name: "ca", Usage: "CA certificate file", Value: ""},
		},
	}
}

func (cmd ValidateCommand) Handle(ctx contracts.Context) error {
	params := crypto.ValidateParams{
		ClientCertFile: ctx.Option("cert"),
		CACertFile:     ctx.Option("ca"),
	}
	crypto.ValidateClientCertificateWithParams(params)
	return nil
}

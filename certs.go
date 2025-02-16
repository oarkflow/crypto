package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type DigitalSignatureService struct {
	Signer    crypto.Signer
	PublicKey crypto.PublicKey
}

func NewDigitalSignatureService(signer crypto.Signer) *DigitalSignatureService {
	return &DigitalSignatureService{
		Signer:    signer,
		PublicKey: signer.Public(),
	}
}

func NewDigitalSignatureServiceFromPublic(pub crypto.PublicKey) *DigitalSignatureService {
	return &DigitalSignatureService{
		PublicKey: pub,
	}
}

func (dss *DigitalSignatureService) SignData(data []byte) ([]byte, error) {
	switch dss.Signer.(type) {
	case ed25519.PrivateKey:
		return dss.Signer.Sign(rand.Reader, data, crypto.Hash(0))
	default:
		h := sha256.New()
		h.Write(data)
		hashed := h.Sum(nil)
		return dss.Signer.Sign(rand.Reader, hashed, crypto.SHA256)
	}
}

func (dss *DigitalSignatureService) VerifyData(data, signature []byte) error {
	switch pub := dss.PublicKey.(type) {
	case ed25519.PublicKey:
		if ed25519.Verify(pub, data, signature) {
			return nil
		}
		return errors.New("ed25519 signature verification failed")
	case *rsa.PublicKey:
		h := sha256.New()
		h.Write(data)
		hashed := h.Sum(nil)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, signature)
	case *ecdsa.PublicKey:
		h := sha256.New()
		h.Write(data)
		hashed := h.Sum(nil)
		var sig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(signature, &sig); err != nil {
			return err
		}
		if ecdsa.Verify(pub, hashed, sig.R, sig.S) {
			return nil
		}
		return errors.New("ecdsa signature verification failed")
	default:
		return errors.New("unsupported public key type")
	}
}

func (dss *DigitalSignatureService) SignText(text string) ([]byte, error) {
	return dss.SignData([]byte(text))
}

func (dss *DigitalSignatureService) VerifyText(text string, signature []byte) error {
	return dss.VerifyData([]byte(text), signature)
}

func (dss *DigitalSignatureService) SignJSON(v interface{}) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return dss.SignData(b)
}

func (dss *DigitalSignatureService) VerifyJSON(v interface{}, signature []byte) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return dss.VerifyData(b, signature)
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

type CAParams struct {
	OrganizationName string
	Country          string
	Curve            string
	CommonName       string
	CertOut          string
	KeyOut           string
}

func GenerateCAWithParams(params CAParams) {
	certDER, caKey := generateCA(params)
	saveCertificate(params.CertOut, certDER)
	savePrivateKey(params.KeyOut, caKey)

	signFileContent(params.CertOut, caKey)
	fmt.Printf("CA certificate and key saved as %s and %s\n", params.CertOut, params.KeyOut)
}

type ServerParams struct {
	CACertFile string
	CAKeyFile  string
	KeyType    string
	Param      string
	CommonName string
	DNSNames   string
	IPList     string
	CertOut    string
	KeyOut     string
}

func GenerateServerWithParams(params ServerParams) {
	caCert, err := loadCertificate(params.CACertFile)
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}
	caKey, err := loadPrivateKey(params.CAKeyFile)
	if err != nil {
		log.Fatalf("Failed to load CA private key: %v", err)
	}

	dnsNames := strings.Split(params.DNSNames, ",")
	for i := range dnsNames {
		dnsNames[i] = strings.TrimSpace(dnsNames[i])
	}
	ipStrs := strings.Split(params.IPList, ",")
	var ips []net.IP
	for _, ipStr := range ipStrs {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	var curveOrBits interface{}
	if strings.ToUpper(params.KeyType) == "ECDSA" {
		curveOrBits = params.Param
	} else if strings.ToUpper(params.KeyType) == "RSA" {
		bits, err := strconv.Atoi(params.Param)
		if err != nil {
			log.Fatalf("Invalid RSA bits parameter: %v", err)
		}
		curveOrBits = bits
	} else {
		log.Fatal("Unsupported key type. Choose ECDSA or RSA.")
	}

	certDER, srvKey := generateServerCert(caCert, caKey, params.KeyType, curveOrBits, params.CommonName, dnsNames, ips)
	saveCertificate(params.CertOut, certDER)
	savePrivateKey(params.KeyOut, srvKey)
	signFileContent(params.CertOut, caKey)
	fmt.Printf("Server certificate and key saved as %s and %s\n", params.CertOut, params.KeyOut)
}

type ClientParams struct {
	CACertFile string
	CAKeyFile  string
	CommonName string
	CertOut    string
	KeyOut     string
}

func GenerateClientWithParams(params ClientParams) {
	caCert, err := loadCertificate(params.CACertFile)
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}
	caKey, err := loadPrivateKey(params.CAKeyFile)
	if err != nil {
		log.Fatalf("Failed to load CA private key: %v", err)
	}

	certDER, clientKey := generateClientCert(caCert, caKey, params.CommonName)
	saveCertificate(params.CertOut, certDER)
	savePrivateKey(params.KeyOut, clientKey)
	signFileContent(params.CertOut, caKey)
	fmt.Printf("Client certificate and key saved as %s and %s\n", params.CertOut, params.KeyOut)
}

type CodeSignParams struct {
	CACertFile string
	CAKeyFile  string
	CommonName string
	RsaBits    int
	CertOut    string
	KeyOut     string
}

func GenerateCodeSignWithParams(params CodeSignParams) {
	caCert, err := loadCertificate(params.CACertFile)
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}
	caKey, err := loadPrivateKey(params.CAKeyFile)
	if err != nil {
		log.Fatalf("Failed to load CA private key: %v", err)
	}
	certDER, csKey := generateCodeSigningCert(caCert, caKey, params.RsaBits, params.CommonName)
	saveCertificate(params.CertOut, certDER)
	savePrivateKey(params.KeyOut, csKey)
	signFileContent(params.CertOut, caKey)
	fmt.Printf("Code-signing certificate and key saved as %s and %s\n", params.CertOut, params.KeyOut)
}

type CRLParams struct {
	CACertFile string
	CAKeyFile  string
	Revoked    string
	CRLOut     string
}

func GenerateCRLWithParams(params CRLParams) {
	if params.Revoked == "" {
		log.Fatal("Please provide at least one revoked certificate serial number")
	}
	var revokedCerts []pkix.RevokedCertificate
	for _, s := range strings.Split(params.Revoked, ",") {
		s = strings.TrimSpace(s)
		serial := new(big.Int)
		_, ok := serial.SetString(s, 10)
		if !ok {
			log.Fatalf("Invalid serial number: %s", s)
		}
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: time.Now(),
		})
	}

	caCert, err := loadCertificate(params.CACertFile)
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}
	caKey, err := loadPrivateKey(params.CAKeyFile)
	if err != nil {
		log.Fatalf("Failed to load CA private key: %v", err)
	}

	crlBytes := generateCRL(caCert, caKey, revokedCerts)
	saveCRL(params.CRLOut, crlBytes)
	signFileContent(params.CRLOut, caKey)
	fmt.Printf("CRL saved as %s\n", params.CRLOut)
}

type SignParams struct {
	FileToSign string
	KeyFile    string
	OutSig     string
}

func SignFileWithParams(params SignParams) {
	signer, err := loadPrivateKey(params.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}
	data, err := os.ReadFile(params.FileToSign)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}
	sig, err := signData(data, signer)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}
	outSig := params.OutSig
	if outSig == "" {
		outSig = params.FileToSign + ".sig"
	}
	err = os.WriteFile(outSig, sig, 0644)
	if err != nil {
		log.Fatalf("Failed to write signature file: %v", err)
	}
	fmt.Printf("File %s signed successfully. Signature saved to %s\n", params.FileToSign, outSig)
}

type VerifyParams struct {
	FileToVerify string
	SigFile      string
	CertFile     string
}

func VerifyFileSignatureWithParams(params VerifyParams) {
	cert, err := loadCertificate(params.CertFile)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}
	err = verifyFileContentSignature(params.FileToVerify, params.SigFile, cert.PublicKey)
	if err != nil {
		log.Fatalf("Signature verification failed: %v", err)
	}
	fmt.Println("Signature verification succeeded.")
}

type SignTextParams struct {
	KeyFile string
	Text    string
	OutSig  string
}

func SignTextWithParams(params SignTextParams) {
	signer, err := loadPrivateKey(params.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}
	dss := NewDigitalSignatureService(signer)
	sig, err := dss.SignText(params.Text)
	if err != nil {
		log.Fatalf("Failed to sign text: %v", err)
	}
	encodedSig := encodeBase64(sig)
	if params.OutSig != "" {
		err = os.WriteFile(params.OutSig, []byte(encodedSig), 0644)
		if err != nil {
			log.Fatalf("Failed to write signature to file: %v", err)
		}
		fmt.Printf("Text signature saved to %s\n", params.OutSig)
	} else {
		fmt.Printf("Text Signature (base64): %s\n", encodedSig)
	}
}

type VerifyTextParams struct {
	CertFile  string
	Text      string
	Signature string
}

func VerifyTextWithParams(params VerifyTextParams) {
	cert, err := loadCertificate(params.CertFile)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}
	dss := NewDigitalSignatureServiceFromPublic(cert.PublicKey)
	sigBytes, err := decodeBase64(params.Signature)
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
	}
	err = dss.VerifyText(params.Text, sigBytes)
	if err != nil {
		log.Fatalf("Text signature verification failed: %v", err)
	}
	fmt.Println("Text signature verification succeeded.")
}

type SignJSONParams struct {
	KeyFile string
	JSONStr string
	OutSig  string
}

func SignJSONWithParams(params SignJSONParams) {
	signer, err := loadPrivateKey(params.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}
	dss := NewDigitalSignatureService(signer)
	var data interface{}
	err = json.Unmarshal([]byte(params.JSONStr), &data)
	if err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}
	sig, err := dss.SignJSON(data)
	if err != nil {
		log.Fatalf("Failed to sign JSON: %v", err)
	}
	encodedSig := encodeBase64(sig)
	if params.OutSig != "" {
		err = os.WriteFile(params.OutSig, []byte(encodedSig), 0644)
		if err != nil {
			log.Fatalf("Failed to write signature to file: %v", err)
		}
		fmt.Printf("JSON signature saved to %s\n", params.OutSig)
	} else {
		fmt.Printf("JSON Signature (base64): %s\n", encodedSig)
	}
}

type VerifyJSONParams struct {
	CertFile  string
	JSONStr   string
	Signature string
}

func VerifyJSONWithParams(params VerifyJSONParams) {
	cert, err := loadCertificate(params.CertFile)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}
	dss := NewDigitalSignatureServiceFromPublic(cert.PublicKey)
	var data interface{}
	err = json.Unmarshal([]byte(params.JSONStr), &data)
	if err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}
	sigBytes, err := decodeBase64(params.Signature)
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
	}
	err = dss.VerifyJSON(data, sigBytes)
	if err != nil {
		log.Fatalf("JSON signature verification failed: %v", err)
	}
	fmt.Println("JSON signature verification succeeded.")
}

type InspectParams struct {
	CertFile string
}

func InspectCertificateWithParams(params InspectParams) {
	err := inspectCertificate(params.CertFile)
	if err != nil {
		log.Fatalf("Inspection failed: %v", err)
	}
}

type ValidateParams struct {
	ClientCertFile string
	CACertFile     string
}

func ValidateClientCertificateWithParams(params ValidateParams) {
	err := validateClientCert(params.ClientCertFile, params.CACertFile)
	if err != nil {
		log.Fatalf("Validation failed: %v", err)
	}
	fmt.Println("Certificate validation succeeded.")
}

func generateCA(params CAParams) ([]byte, crypto.Signer) {
	privKey, err := generatePrivateKey("ECDSA", params.Curve)
	if err != nil {
		log.Fatal("CA key generation failed:", err)
	}
	subject := pkix.Name{
		CommonName:   params.CommonName,
		Organization: []string{params.OrganizationName},
		Country:      []string{params.Country},
	}
	template := x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		log.Fatal("CA cert creation failed:", err)
	}
	return certBytes, privKey
}

func generateServerCert(caCert *x509.Certificate, caKey crypto.Signer, keyType string, curveOrBits interface{}, commonName string, dnsNames []string, ips []net.IP) ([]byte, crypto.Signer) {
	privKey, err := generatePrivateKey(keyType, curveOrBits)
	if err != nil {
		log.Fatal("Server key generation failed:", err)
	}
	template := x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, privKey.Public(), caKey)
	if err != nil {
		log.Fatal("Server cert creation failed:", err)
	}
	return certBytes, privKey
}

func generateClientCert(caCert *x509.Certificate, caKey crypto.Signer, commonName string) ([]byte, crypto.Signer) {
	privKey, err := generatePrivateKey("Ed25519", nil)
	if err != nil {
		log.Fatal("Client key generation failed:", err)
	}
	template := x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, privKey.Public(), caKey)
	if err != nil {
		log.Fatal("Client cert creation failed:", err)
	}
	return certBytes, privKey
}

func generateCodeSigningCert(caCert *x509.Certificate, caKey crypto.Signer, rsaBits int, commonName string) ([]byte, crypto.Signer) {
	privKey, err := generatePrivateKey("RSA", rsaBits)
	if err != nil {
		log.Fatal("Code signing key generation failed:", err)
	}
	template := x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(5, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, privKey.Public(), caKey)
	if err != nil {
		log.Fatal("Code signing cert creation failed:", err)
	}
	return certBytes, privKey
}

func generateCRL(caCert *x509.Certificate, caKey crypto.Signer, revoked []pkix.RevokedCertificate) []byte {
	crlTemplate := &x509.RevocationList{
		SignatureAlgorithm:  caCert.SignatureAlgorithm,
		RevokedCertificates: revoked,
		Number:              randomSerial(),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().AddDate(0, 1, 0),
		Issuer:              caCert.Subject,
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		log.Fatal("CRL creation failed:", err)
	}
	return crlBytes
}

func generatePrivateKey(algo string, param interface{}) (crypto.Signer, error) {
	switch algo {
	case "RSA":
		bits, ok := param.(int)
		if !ok {
			return nil, fmt.Errorf("invalid RSA parameter")
		}
		return rsa.GenerateKey(rand.Reader, bits)
	case "ECDSA":
		curveName, ok := param.(string)
		if !ok {
			return nil, fmt.Errorf("invalid ECDSA parameter")
		}
		var curve elliptic.Curve
		switch curveName {
		case "P224":
			curve = elliptic.P224()
		case "P256":
			curve = elliptic.P256()
		case "P384":
			curve = elliptic.P384()
		case "P521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve")
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "Ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported algorithm")
	}
}

func randomSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatal("failed to generate serial number:", err)
	}
	return serial
}

func saveCertificate(filename string, cert []byte) {
	err := os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}), 0644)
	if err != nil {
		log.Fatal("Failed to save certificate:", err)
	}
}

func savePrivateKey(filename string, key crypto.Signer) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal("Failed to marshal private key:", err)
	}
	err = os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}), 0600)
	if err != nil {
		log.Fatal("Failed to save private key:", err)
	}
}

func saveCRL(filename string, crl []byte) {
	err := os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	}), 0644)
	if err != nil {
		log.Fatal("Failed to save CRL:", err)
	}
}

func signFileContent(filename string, signer crypto.Signer) {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal("Failed to read file for signing:", err)
	}
	sig, err := signData(data, signer)
	if err != nil {
		log.Fatal("Failed to sign file content:", err)
	}
	err = os.WriteFile(filename+".sig", sig, 0644)
	if err != nil {
		log.Fatal("Failed to save signature file:", err)
	}
}

func signData(data []byte, key crypto.Signer) ([]byte, error) {
	switch key.(type) {
	case ed25519.PrivateKey:
		return key.Sign(rand.Reader, data, crypto.Hash(0))
	default:
		h := sha256.New()
		h.Write(data)
		hashed := h.Sum(nil)
		return key.Sign(rand.Reader, hashed, crypto.SHA256)
	}
}

func verifyDataSignature(data, signature []byte, pub crypto.PublicKey) error {
	switch pub := pub.(type) {
	case ed25519.PublicKey:
		if ed25519.Verify(pub, data, signature) {
			return nil
		}
		return errors.New("ed25519 signature verification failed")
	case *rsa.PublicKey:
		h := sha256.New()
		h.Write(data)
		hashed := h.Sum(nil)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, signature)
	case *ecdsa.PublicKey:
		h := sha256.New()
		h.Write(data)
		hashed := h.Sum(nil)
		var sig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(signature, &sig); err != nil {
			return err
		}
		if ecdsa.Verify(pub, hashed, sig.R, sig.S) {
			return nil
		}
		return errors.New("ecdsa signature verification failed")
	default:
		return errors.New("unsupported public key type")
	}
}

func verifyFileContentSignature(filename, sigFilename string, pub crypto.PublicKey) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	sig, err := os.ReadFile(sigFilename)
	if err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}
	return verifyDataSignature(data, sig, pub)
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM from %s", filename)
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadPrivateKey(filename string) (crypto.Signer, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM from %s", filename)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("not a valid crypto.Signer key")
	}
	return signer, nil
}

func validateClientCert(clientCertPath, caCertPath string) error {
	caCert, err := loadCertificate(caCertPath)
	if err != nil {
		return err
	}
	clientCert, err := loadCertificate(clientCertPath)
	if err != nil {
		return err
	}
	opts := x509.VerifyOptions{
		Roots:     x509.NewCertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	opts.Roots.AddCert(caCert)
	if _, err = clientCert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}
	if err = verifyFileContentSignature(clientCertPath, clientCertPath+".sig", caCert.PublicKey); err != nil {
		return fmt.Errorf("file signature verification failed: %w", err)
	}
	return nil
}

func inspectCertificate(filename string) error {
	cert, err := loadCertificate(filename)
	if err != nil {
		return err
	}
	fmt.Printf("Certificate: %s\n", filename)
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Issuer: %s\n", cert.Issuer)
	fmt.Printf("  Serial: %s\n", cert.SerialNumber)
	fmt.Printf("  Valid From: %s\n", cert.NotBefore)
	fmt.Printf("  Valid To  : %s\n", cert.NotAfter)
	fmt.Printf("  Key Usage : %v\n", cert.KeyUsage)
	return nil
}

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

type CertificateInfo struct {
	Organization  string
	Country       string
	Province      string
	Locality      string
	StreetAddress string
	PostalCode    string
}

// generateKey creates a new RSA private key
func generateKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return key, nil
}

// savePEMKey saves a private key to a PEM file
func savePEMKey(fileName string, key *rsa.PrivateKey) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", fileName, err)
	}
	defer outFile.Close()

	privateKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	if err := pem.Encode(outFile, &privateKeyPEM); err != nil {
		return fmt.Errorf("failed to write data to %s: %w", fileName, err)
	}

	return nil
}

// savePEMCert saves a certificate to a PEM file
func savePEMCert(fileName string, cert []byte) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", fileName, err)
	}
	defer outFile.Close()

	certPEM := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	if err := pem.Encode(outFile, &certPEM); err != nil {
		return fmt.Errorf("failed to write data to %s: %w", fileName, err)
	}

	return nil
}

// generateCertificate creates a certificate based on the template and signs it with the signer key and cert
func generateCertificate(template, parent *x509.Certificate, pub interface{}, signer interface{}) ([]byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	return certBytes, nil
}

// loadPEMKey loads an existing private key from a PEM file
func loadPEMKey(fileName string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", fileName, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid key format")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// loadPEMCert loads an existing certificate from a PEM file
func loadPEMCert(fileName string) (*x509.Certificate, error) {
	certData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file %s: %w", fileName, err)
	}

	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid cert format")
	}

	return x509.ParseCertificate(block.Bytes)
}

// createCertificateAuthority generates a self-signed root CA certificate
func createCertificateAuthority(cert CertificateInfo, certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Check if the certificate already exists
	caCert, err := loadPEMCert(certPath)
	if err == nil {
		// Certificate exists, load the private key
		caKey, err := loadPEMKey(keyPath)
		if err == nil {
			// Successfully loaded existing cert and key
			return caCert, caKey, nil
		}
		return nil, nil, fmt.Errorf("failed to load existing private key: %w", err)
	}

	// If we reach here, the cert does not exist; generate a new one
	caKey, err := generateKey()
	if err != nil {
		return nil, nil, err
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{cert.Organization},
			Country:       []string{cert.Country},
			Province:      []string{cert.Province},
			Locality:      []string{cert.Locality},
			StreetAddress: []string{cert.StreetAddress},
			PostalCode:    []string{cert.PostalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertBytes, err := generateCertificate(caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	err = savePEMCert(certPath, caCertBytes)
	if err != nil {
		return nil, nil, err
	}

	err = savePEMKey(keyPath, caKey)
	if err != nil {
		return nil, nil, err
	}

	caCert, err = x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return caCert, caKey, nil
}

// createServerCertificate generates a server certificate signed by the CA, with SANs
func createServerCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey) error {
	serverKey, err := generateKey()
	if err != nil {
		return err
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"My Server"},
			CommonName:   "localhost", // Legacy support, still required by some systems
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},              // Add SANs
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, // Add IP SANs
	}

	serverCertBytes, err := generateCertificate(serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	err = savePEMCert("server-cert.pem", serverCertBytes)
	if err != nil {
		return err
	}

	err = savePEMKey("server-key.pem", serverKey)
	if err != nil {
		return err
	}

	return nil
}

// createClientCertificate generates a client certificate signed by the CA, with SANs
func createClientCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey, commonName, certPath, keyPath string) error {
	clientKey, err := generateKey()
	if err != nil {
		return err
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"My Client"},
			CommonName:   commonName, // Can be set to identify the client
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"client.local"}, // Add SANs for the client
	}

	clientCertBytes, err := generateCertificate(clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	err = savePEMCert(certPath, clientCertBytes)
	if err != nil {
		return err
	}

	err = savePEMKey(keyPath, clientKey)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	certInfo := CertificateInfo{
		Organization:  "My CA",
		Country:       "US",
		Province:      "California",
		Locality:      "San Francisco",
		StreetAddress: "123 Main St",
		PostalCode:    "94111",
	}
	// Generate the root CA certificate and key
	caCert, caKey, err := createCertificateAuthority(certInfo, "server-cert.pem", "server-key.pem")
	if err != nil {
		fmt.Println("Error generating CA:", err)
		return
	}

	// Generate the server certificate signed by the CA, with SANs
	err = createServerCertificate(caCert, caKey)
	if err != nil {
		fmt.Println("Error generating server certificate:", err)
		return
	}

	// Generate the client certificate signed by the CA, with SANs
	err = createClientCertificate(caCert, caKey, "Publisher", "publisher-cert.pem", "publisher-key.pem")
	if err != nil {
		fmt.Println("Error generating publisher certificate:", err)
		return
	}

	// Generate the client certificate signed by the CA, with SANs
	err = createClientCertificate(caCert, caKey, "Consumer", "consumer-cert.pem", "consumer-key.pem")
	if err != nil {
		fmt.Println("Error generating publisher certificate:", err)
		return
	}

	fmt.Println("Certificates successfully generated with SANs!")
}

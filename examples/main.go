package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
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

func generateKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return key, nil
}

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

func generateCertificate(template, parent *x509.Certificate, pub interface{}, signer interface{}) ([]byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	return certBytes, nil
}

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

func createCertificateAuthority(cert CertificateInfo, certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	caCert, err := loadPEMCert(certPath)
	if err == nil {
		caKey, err := loadPEMKey(keyPath)
		if err == nil {
			return caCert, caKey, nil
		}
		return nil, nil, fmt.Errorf("failed to load existing private key: %w", err)
	}
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
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
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

func createServerCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey, certPath, keyPath, commonName string, dnsNames, ipAddresses []string) error {
	serverKey, err := generateKey()
	if err != nil {
		return err
	}
	var ips []net.IP
	for _, ip := range ipAddresses {
		ips = append(ips, net.ParseIP(ip))
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"My Server"},
			CommonName:   commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	serverCertBytes, err := generateCertificate(serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	err = savePEMCert(certPath, serverCertBytes)
	if err != nil {
		return err
	}
	err = savePEMKey(keyPath, serverKey)
	if err != nil {
		return err
	}
	return nil
}

func createClientCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey, commonName, certPath, keyPath, organization string, dnsNames []string) error {
	clientKey, err := generateKey()
	if err != nil {
		return err
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    dnsNames,
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
	// Define command-line flags
	caCertPath := flag.String("ca-cert", "ca-cert.pem", "Path to the CA certificate file")
	caKeyPath := flag.String("ca-key", "ca-key.pem", "Path to the CA key file")
	serverCertPath := flag.String("server-cert", "server-cert.pem", "Path to the server certificate file")
	serverKeyPath := flag.String("server-key", "server-key.pem", "Path to the server key file")
	publisherCertPath := flag.String("publisher-cert", "publisher-cert.pem", "Path to the publisher certificate file")
	publisherKeyPath := flag.String("publisher-key", "publisher-key.pem", "Path to the publisher key file")
	consumerCertPath := flag.String("consumer-cert", "consumer-cert.pem", "Path to the consumer certificate file")
	consumerKeyPath := flag.String("consumer-key", "consumer-key.pem", "Path to the consumer key file")
	orgName := flag.String("org", "My CA", "Organization name for the CA certificate")
	country := flag.String("country", "US", "Country for the CA certificate")
	province := flag.String("province", "California", "Province for the CA certificate")
	locality := flag.String("locality", "San Francisco", "Locality for the CA certificate")
	streetAddress := flag.String("street", "123 Main St", "Street address for the CA certificate")
	postalCode := flag.String("postal", "94111", "Postal code for the CA certificate")
	dnsNames := flag.String("dns", "localhost", "Comma-separated DNS names for the server and client certificates")
	ipAddresses := flag.String("ip", "127.0.0.1", "Comma-separated IP addresses for the server certificate")
	clientCommonName := flag.String("client-cname", "Client", "Common name for the client certificate")

	flag.Parse()

	// Parse DNS and IP addresses
	dnsList := strings.Split(*dnsNames, ",")
	ipList := strings.Split(*ipAddresses, ",")

	// Create CA certificate
	caCertInfo := CertificateInfo{
		Organization:  *orgName,
		Country:       *country,
		Province:      *province,
		Locality:      *locality,
		StreetAddress: *streetAddress,
		PostalCode:    *postalCode,
	}

	caCert, caKey, err := createCertificateAuthority(caCertInfo, *caCertPath, *caKeyPath)
	if err != nil {
		fmt.Printf("Error creating CA: %v\n", err)
		return
	}

	// Create server certificate
	err = createServerCertificate(caCert, caKey, *serverCertPath, *serverKeyPath, "My Server", dnsList, ipList)
	if err != nil {
		fmt.Printf("Error creating server certificate: %v\n", err)
		return
	}

	// Create client certificate
	err = createClientCertificate(caCert, caKey, *clientCommonName, *publisherCertPath, *publisherKeyPath, *orgName, dnsList)
	if err != nil {
		fmt.Printf("Error creating client certificate: %v\n", err)
		return
	}

	// Create client certificate
	err = createClientCertificate(caCert, caKey, *clientCommonName, *consumerCertPath, *consumerKeyPath, *orgName, dnsList)
	if err != nil {
		fmt.Printf("Error creating client certificate: %v\n", err)
		return
	}

	fmt.Println("Certificates generated successfully.")
}

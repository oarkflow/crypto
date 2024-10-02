package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

func main() {
	// Load client certificate
	cert, err := tls.LoadX509KeyPair("consumer-cert.pem", "consumer-key.pem")
	if err != nil {
		fmt.Println("Failed to load client certificate:", err)
		return
	}

	// Load CA certificate
	caCert, err := ioutil.ReadFile("ca-cert.pem")
	if err != nil {
		fmt.Println("Failed to load CA cert:", err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Connect to the server
	conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
	if err != nil {
		fmt.Println("Failed to connect to server:", err)
		return
	}
	defer conn.Close()

	// Receive messages from server
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Failed to read from server:", err)
			return
		}
		message := string(buf[:n])
		fmt.Println("Received from server:", message)
	}
}

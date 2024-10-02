package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"
)

func main() {
	// Load client certificate
	cert, err := tls.LoadX509KeyPair("publisher-cert.pem", "publisher-key.pem")
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

	// Send messages
	for i := 0; i < 5; i++ {
		message := fmt.Sprintf("Message %d from publisher", i+1)
		fmt.Println("Sending message:", message)

		_, err = conn.Write([]byte(message))
		if err != nil {
			fmt.Println("Failed to send message:", err)
			return
		}

		time.Sleep(2 * time.Second) // Wait between messages
	}
}

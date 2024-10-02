package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

func main() {

	cert, err := tls.LoadX509KeyPair("publisher-cert.pem", "publisher-key.pem")
	if err != nil {
		fmt.Println("Failed to load client certificate:", err)
		return
	}

	caCert, err := os.ReadFile("ca-cert.pem")
	if err != nil {
		fmt.Println("Failed to load CA cert:", err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
	if err != nil {
		fmt.Println("Failed to connect to server:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte("publisher"))
	if err != nil {
		fmt.Println("Failed to send client type:", err)
		return
	}

	for i := 0; i < 5; i++ {
		message := fmt.Sprintf("Message %d from publisher", i+1)
		fmt.Println("Sending message:", message)
		_, err = conn.Write([]byte(message))
		if err != nil {
			fmt.Println("Failed to send message:", err)
			return
		}
		time.Sleep(2 * time.Second)
	}
}

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func main() {

	cert, err := tls.LoadX509KeyPair("consumer-cert.pem", "consumer-key.pem")
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

	_, err = conn.Write([]byte("consumer"))
	if err != nil {
		fmt.Println("Failed to send client type:", err)
		return
	}

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

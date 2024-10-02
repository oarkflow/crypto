package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"time"
)

var (
	messages = make(chan string, 10) // Channel for storing messages from publisher to consumer
	wg       sync.WaitGroup
)

// createTLSServer starts a TLS listener with mutual authentication enabled
func createTLSServer(certPath, keyPath, caPath string) (*net.Listener, error) {
	// Load server certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert/key: %w", err)
	}

	// Load CA certificate for client verification
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Start TLS listener
	ln, err := tls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to start TLS listener: %w", err)
	}

	return &ln, nil
}

// handlePublisher listens for messages from the publisher and forwards them to the consumer
func handlePublisher(conn net.Conn) {
	defer conn.Close()
	defer wg.Done()

	fmt.Println("Handling publisher connection...")

	// Add a timeout for reading from the publisher connection to prevent blocking indefinitely
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Publisher connection closed or error:", err)
			return
		}

		message := string(buf[:n])
		fmt.Println("Received from publisher:", message)

		// Forward the message to the consumer
		messages <- message
	}
}

// handleConsumer sends messages to the consumer
func handleConsumer(conn net.Conn) {
	defer conn.Close()
	defer wg.Done()

	fmt.Println("Handling consumer connection...")

	// Add a timeout for reading messages from the channel to avoid indefinite blocking
	for {
		select {
		case msg := <-messages:
			fmt.Println("Sending to consumer:", msg)
			_, err := conn.Write([]byte(msg))
			if err != nil {
				fmt.Println("Failed to send to consumer:", err)
				return
			}
		case <-time.After(30 * time.Second):
			fmt.Println("No messages to send to consumer, timing out.")
			return
		}
	}
}

func main() {
	// Start the TLS server
	listener, err := createTLSServer("server-cert.pem", "server-key.pem", "ca-cert.pem")
	if err != nil {
		fmt.Println("Failed to create TLS server:", err)
		return
	}
	defer (*listener).Close()

	fmt.Println("Server started on port 8443")

	// Accept connections from publisher and consumer
	for {
		conn, err := (*listener).Accept()
		if err != nil {
			fmt.Println("Failed to accept connection:", err)
			continue
		}

		// Ensure it's a TLS connection
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			fmt.Println("Connection is not a TLS connection")
			conn.Close()
			continue
		}

		// Perform the handshake to complete TLS negotiation
		err = tlsConn.Handshake()
		if err != nil {
			fmt.Println("TLS handshake failed:", err)
			tlsConn.Close()
			continue
		}

		// Now it's safe to access PeerCertificates
		peerCerts := tlsConn.ConnectionState().PeerCertificates
		if len(peerCerts) == 0 {
			fmt.Println("No peer certificates found")
			tlsConn.Close()
			continue
		}

		fmt.Println("Accepted connection from:", peerCerts[0].Subject.CommonName)

		// Determine if the connection is a publisher or a consumer
		if peerCerts[0].Subject.CommonName == "Publisher" {
			wg.Add(1)
			go handlePublisher(tlsConn)
		} else if peerCerts[0].Subject.CommonName == "Consumer" {
			wg.Add(1)
			go handleConsumer(tlsConn)
		}
	}

	wg.Wait()
}

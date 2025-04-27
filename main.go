package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func loadKeyPair(certFile, keyFile, passphrase string) (tls.Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyBlock, _ := pem.Decode(keyPEMBlock)
	if keyBlock == nil {
		return tls.Certificate{}, fmt.Errorf("failed to decode PEM block containing private key")
	}

	decryptedKeyBlock, err := x509.DecryptPEMBlock(keyBlock, []byte(passphrase))
	if err != nil {
		return tls.Certificate{}, err
	}

	key, err := x509.ParsePKCS1PrivateKey(decryptedKeyBlock)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certPEMBlock},
		PrivateKey:  key,
	}

	return cert, nil
}

func main() {
	// Define the passphrase
	passphrase := "your_passphrase_here"

	// Load client certificate and key with passphrase
	cert, err := loadKeyPair("client.crt", "client.key", passphrase)
	if err != nil {
		fmt.Println("Error loading client certificate and key:", err)
		return
	}

	// Load CA certificate
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		fmt.Println("Error loading CA certificate:", err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Set up TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Create HTTPS client with TLS configuration
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{
		Transport: transport,
	}

	// Create request
	req, err := http.NewRequest("POST", "https://example.com/api", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	fmt.Println("Response:", string(body))
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
)

func padPassphrase(passphrase string, length int) []byte {
	padded := make([]byte, length)
	copy(padded, passphrase)
	return padded
}

func decryptKey(encryptedKey []byte, passphrase string) ([]byte, error) {
	key := padPassphrase(passphrase, 32) // Pad passphrase to 16 bytes
	//key := []byte(passphrase) // Use a secure key derivation function in production
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("aes.NewCipher(key) ", err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("cipher.NewGCM(block) ", err)
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := encryptedKey[:nonceSize], encryptedKey[nonceSize:]

	arr, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println("arr, err := gcm.Open(nil, nonce, ciphertext, nil) ", err)
	}

	return arr, err
}

func loadKeyPair(certFile, keyFile, passphrase string) (tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		fmt.Println("ertPEMBlock, err := os.ReadFile(certFile) ", err)
		return tls.Certificate{}, err
	}

	encryptedKeyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Println("encryptedKeyPEMBlock, err := os.ReadFile(keyFile) ", err)
		return tls.Certificate{}, err
	}

	keyBlock, _ := pem.Decode(encryptedKeyPEMBlock)
	if keyBlock == nil {
		fmt.Println("keyBlock, _ := pem.Decode(encryptedKeyPEMBlock) ", err)
		return tls.Certificate{}, fmt.Errorf("failed to decode PEM block containing private key")
	}

	decryptedKey, err := decryptKey(keyBlock.Bytes, passphrase)
	if err != nil {
		fmt.Println("decryptedKey, err := decryptKey(keyBlock.Bytes, passphrase) ", err)
		return tls.Certificate{}, err
	}

	key, err := x509.ParsePKCS1PrivateKey(decryptedKey)
	if err != nil {
		fmt.Println("key, err := x509.ParsePKCS1PrivateKey(decryptedKey) ", err)
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
	passphrase := "1234567890abcdef"

	// Load client certificate and key with passphrase
	cert, err := loadKeyPair("client.crt", "client.key", passphrase)
	if err != nil {
		fmt.Println("Error loading client certificate and key:", err)
		return
	}

	// Load CA certificate
	caCert, err := os.ReadFile("ca.crt")
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	fmt.Println("Response:", string(body))
}

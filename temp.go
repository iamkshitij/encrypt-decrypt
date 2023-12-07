package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

const (
	publicKeyFilePath  = "public_key.pem"
	privateKeyFilePath = "private_key.pem"
)

func generateKeyPair(clientID string) (string, string, error) {
	// Check if both PEM files already exist
	if _, err := os.Stat(publicKeyFilePath); err == nil && fileExists(privateKeyFilePath) {
		// Files exist, read and return their contents
		publicKeyBytes, err := os.ReadFile(publicKeyFilePath)
		if err != nil {
			return "", "", err
		}

		privateKeyBytes, err := os.ReadFile(privateKeyFilePath)
		if err != nil {
			return "", "", err
		}

		return string(publicKeyBytes), string(privateKeyBytes), nil
	}

	// Files do not exist, generate a new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Save the public and private keys to the file system
	err = os.WriteFile(publicKeyFilePath, publicKeyPEM, 0644)
	if err != nil {
		return "", "", err
	}

	err = os.WriteFile(privateKeyFilePath, privateKeyPEM, 0600)
	if err != nil {
		return "", "", err
	}

	return string(publicKeyPEM), string(privateKeyPEM), nil
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

func main() {
	clientID := "exampleClientID"
	publicKey, privateKey, err := generateKeyPair(clientID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Public Key:")
	fmt.Println(publicKey)

	fmt.Println("\nPrivate Key:")
	fmt.Println(privateKey)
}

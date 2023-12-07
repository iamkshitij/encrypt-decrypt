package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	pb "go-grpc/middleware/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"os"
)

func (s *Server) Handshake(ctx context.Context, in *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
	log.Println("Inside Handshake middleware")
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to get metadata")
	}
	// Access a service type header value
	serviceType := md.Get("x-service-type")
	fmt.Printf("Service type from header: %s\n", serviceType[0])

	publicKeyStr, blockBytes, err := getPublicKeyAndBlock(serviceType[0])

	if err != nil {
		log.Fatalf("Error while generating public key %v", err)
	}

	// generate AES-256
	aesKey, err := generateAES256GCMKey()
	if err != nil {
		log.Fatalf("Error while generating AES256: %v", err)
	}
	log.Printf("Generate Secret key: %s", hex.EncodeToString(aesKey))

	// generate encrypted RSA-256
	publicKey, err := x509.ParsePKIXPublicKey(blockBytes)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
	}

	// Encrypt AES key with RSA public key
	encryptedKey, err := encryptAESKeyWithRSA(aesKey, publicKey.(*rsa.PublicKey))
	if err != nil {
		fmt.Println("Error encrypting AES key with RSA:", err)
	}

	// Encode the encrypted key as base64 and print as a string
	encryptedKeyBase64 := base64.StdEncoding.EncodeToString(encryptedKey)
	fmt.Println("Encrypted AES Key:", encryptedKeyBase64)

	response := &pb.HandshakeResponse{
		Data:       &pb.Data{PublicKey: publicKeyStr},
		Status:     "Handshake Successful",
		StatusCode: 200,
	}

	return response, nil
}

func generateAES256GCMKey() ([]byte, error) {
	// AES-256 uses a 32-byte (256-bit) key
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func encryptAESKeyWithRSA(aesKey []byte, rsaPublicKey *rsa.PublicKey) ([]byte, error) {
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, aesKey)
	if err != nil {
		return nil, err
	}
	return encryptedKey, nil
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

func getPublicKeyAndBlock(serviceType string) (string, []byte, error) {
	log.Println("Inside get public key pair and block")
	// check whether key pairs exists or not
	privateKeyFilePath := "middleware/pem/private_key_" + serviceType + ".pem"
	// Check if both PEM files already exist then return public key and block value
	if _, err := os.Stat(privateKeyFilePath); err == nil {
		// read pem file and return public key and block value
		pemBytes, err := os.ReadFile(privateKeyFilePath)
		if err != nil {
			return "", []byte{}, err
		}

		// Decode the PEM block
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return "", []byte{}, fmt.Errorf("failed to decode PEM block")
		}

		// Parse the private key
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", []byte{}, err
		}

		// Extract the public key from the private key
		publicKey := &privateKey.PublicKey

		bytes, _ := x509.MarshalPKIXPublicKey(publicKey)
		// Encode the public key in PEM format
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: bytes,
		})
		block, _ = pem.Decode(publicKeyPEM)

		publicKeyStr := base64.StdEncoding.EncodeToString(block.Bytes)

		log.Println("Key Pair Exists")
		log.Printf("public key: %s", publicKeyStr)

		return publicKeyStr, block.Bytes, nil
	} else {

		// create a new key pair and return public key and block value
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", []byte{}, err
		}

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return "", []byte{}, err
		}

		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})

		err = os.WriteFile(privateKeyFilePath, privateKeyPEM, 0600)
		if err != nil {
			return "", []byte{}, err
		}
		block, _ := pem.Decode(publicKeyPEM)
		publicKeyStr := base64.StdEncoding.EncodeToString(block.Bytes)

		log.Println("New Key Pair Generated")
		log.Printf("public key: %s", publicKeyStr)

		return publicKeyStr, block.Bytes, nil
	}

}

// Implement this function to generate a public key based on the client ID
func generatePublicKey(serviceType string) (string, []byte, error) {
	// search if file already exists
	publicKeyFilePath := "middleware/pem/public_key_" + serviceType + ".pem"
	// Check if the PEM file already exists
	if _, err := os.Stat(publicKeyFilePath); err == nil {
		// File exists, read and return its contents
		log.Printf("File already exists: %s", publicKeyFilePath)
		publicKeyBytes, err := os.ReadFile(publicKeyFilePath)
		if err != nil {
			return "", []byte{}, err
		}
		log.Printf("Public key values: %s", string(publicKeyBytes))
		return string(publicKeyBytes), []byte{}, nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", []byte{}, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", []byte{}, err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	block, _ := pem.Decode(publicKeyPEM)

	if err != nil {
		fmt.Println("Error parsing public key:", err)
	}

	publicKeyStr := base64.StdEncoding.EncodeToString(block.Bytes)

	// Save the public key to the file system
	err = os.WriteFile(publicKeyFilePath, publicKeyPEM, 0644)
	if err != nil {
		return "", []byte{}, err
	}

	return publicKeyStr, block.Bytes, nil
}

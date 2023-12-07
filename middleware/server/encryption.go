package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	pb "go-grpc/middleware/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"os"
)

func (s *Server) Encryption(ctx context.Context, in *pb.EncryptionRequest) (*pb.EncryptionResponse, error) {

	log.Println("Inside encryption middleware")
	// get x-service-type and x-api-encryption-key from header

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "Failed to get metadata")
	}

	// Access a service type header value
	serviceType := md.Get("x-service-type")[0]
	apiEncryptionKey := md.Get("x-api-encryption-key")[0]
	// get requestData from Request
	requestData := in.RequestData

	log.Printf("service type: %s apiEncrptyion: %s RequestData: %s", serviceType, apiEncryptionKey, requestData)

	// get secret key from encryption secret key
	privateKeyPath := "middleware/pem/private_key_" + serviceType + ".pem"
	plainText, err := decryptRSA([]byte(apiEncryptionKey), privateKeyPath)
	if err != nil {
		log.Fatalf("Error while decrypting RSA %v", err.Error())
	}

	log.Printf("Plain Text: %s", string(plainText))

	////key, err := getEncryptionKeyFromContext(ctx)
	//key := "9c34c672c37cd49944f9e74b0958180e"
	////if err != nil {
	////	return nil, fmt.Errorf("failed to get encryption key: %v", err)
	////}
	//
	//// Generate a random nonce
	//nonce := make([]byte, 12)
	//if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
	//	return nil, fmt.Errorf("failed to generate nonce: %v", err)
	//}
	//fmt.Printf("%s", in.GetRequestData())
	//// Encrypt the data using AES-256-GCM
	//encryptedData, err := encryptData([]byte(key), nonce, []byte(in.GetRequestData()))
	//if err != nil {
	//	return nil, fmt.Errorf("failed to encrypt data: %v", err)
	//}
	//
	//// Concatenate nonce, authentication tag, and encrypted payload with a separator
	//joinedResult := fmt.Sprintf("%x.%x.%x", nonce, encryptedData[:12], encryptedData[12:])
	//
	//response := &pb.EncryptionResponse{
	//	Payload: joinedResult,
	//}

	//return response, nil
	return &pb.EncryptionResponse{}, nil
}

// Encrypts data using AES-256-GCM
func encryptData(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	fmt.Println(nonce, plaintext)

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nil
}

// Extract encryption key from context headers
func getEncryptionKeyFromContext(ctx context.Context) ([]byte, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("metadata not found in context")
	}

	keys, exists := md["x-api-encryption-key"]
	if !exists || len(keys) == 0 {
		return nil, fmt.Errorf("x-api-encryption-key not found in headers")
	}

	key := keys[0]

	log.Println("Key from x-client", key)

	// Decode base64-encoded key
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	log.Println("Decoded key", string(decodedKey))
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %v", err)
	}

	return decodedKey, nil
}

func decryptRSA(ciphertext []byte, privateKeyPath string) ([]byte, error) {
	// Load the private key from the file
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("Error while reading pk: %v", err)
		return nil, err
	}

	//log.Printf("Private key: %s\n ", string(privateKeyBytes))
	// Decode the PEM-encoded private key
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	log.Printf("Block Type: %v", block.Type)
	log.Println("headers: ", block.Headers)
	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error while ParsePKCS1PrivateKey: %v", err)
		return nil, err
	}
	log.Println("Cipher Text", string(ciphertext))
	// Decrypt the ciphertext using the private key
	//plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)

	if err != nil {
		log.Fatalf("Error while DecryptPKCS1v15: %v", err)
		return nil, err
	}

	return plaintext, nil
}

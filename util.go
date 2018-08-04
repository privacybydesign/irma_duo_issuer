package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

// Utility function to read the entire contents of a file.
func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ioutil.ReadAll(file)
}

// Utility function to read a PEM-encoded private key from a given path.
func readPrivateKey(path string) (*rsa.PrivateKey, error) {
	// https://stackoverflow.com/a/44231740/559350
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("cannot parse PEM-encoded private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Utility function to read a PEM-encoded public key from a given path.
func readPublicKey(path string) (*rsa.PublicKey, error) {
	// https://stackoverflow.com/a/44231740/559350
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("cannot parse PEM-encoded public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if key, ok := key.(*rsa.PublicKey); ok {
		return key, nil
	} else {
		return nil, errors.New("cannot determine public key type")
	}
}

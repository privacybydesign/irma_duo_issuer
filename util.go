package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

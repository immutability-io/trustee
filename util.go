// Copyright © 2018 Immutability, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/logical"
)

const (
	// JWTAlgorithm is for secp256k1
	JWTAlgorithm string = "ES256"
	// ProtocolKeystore JSON keystore URLs start with this
	ProtocolKeystore string = "keystore://"
	// MaxKeystoreSize is a heuristic to prevent reading stupid big files
	MaxKeystoreSize int64 = 1024
	// RequestPathImport is the part of the path for import
	RequestPathImport string = "import"
	// RequestPathTrustees is the part of the path for trustees
	RequestPathTrustees string = "trustees"
	// PassphraseWords is the default number of words in a passphrase
	PassphraseWords int = 9
	// PassphraseSeparator separates PassphraseWords
	PassphraseSeparator string = "-"
)

func prettyPrint(v interface{}) string {
	jsonString, _ := json.Marshal(v)
	var out bytes.Buffer
	json.Indent(&out, jsonString, "", "  ")
	return out.String()
}

func (b *backend) writeTemporaryKeystoreFile(path string, filename string, data []byte) (string, error) {
	keystorePath := path + "/" + filename
	err := ioutil.WriteFile(keystorePath, data, 0644)
	return keystorePath, err
}

func (b *backend) createTemporaryKeystoreDirectory() (string, error) {
	dir, err := ioutil.TempDir("", "keystore")
	return dir, err
}

func (b *backend) removeTemporaryKeystore(path string) error {
	return os.RemoveAll(path)
}

func convertMapToStringValue(initial map[string]interface{}) map[string]string {
	result := map[string]string{}
	for key, value := range initial {
		result[key] = fmt.Sprintf("%v", value)
	}
	return result
}

func parseURL(url string) (accounts.URL, error) {
	parts := strings.Split(url, "://")
	if len(parts) != 2 || parts[0] == "" {
		return accounts.URL{}, errors.New("protocol scheme missing")
	}
	return accounts.URL{
		Scheme: parts[0],
		Path:   parts[1],
	}, nil
}

func (b *backend) importJSONKeystore(ctx context.Context, keystorePath string, passphrase string) (*ecdsa.PrivateKey, error) {
	var key *keystore.Key
	jsonKeystore, err := b.readJSONKeystore(keystorePath)
	if err != nil {
		return nil, err
	}
	key, err = keystore.DecryptKey(jsonKeystore, passphrase)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("failed to decrypt key")
	}

	return key.PrivateKey, err
}

func pathExists(ctx context.Context, req *logical.Request, path string) (bool, error) {
	out, err := req.Storage.Get(ctx, path)
	if err != nil {
		return false, fmt.Errorf("existence check failed for %s: %v", path, err)
	}

	return out != nil, nil
}

func (b *backend) readJSONKeystore(keystorePath string) ([]byte, error) {
	var jsonKeystore []byte
	file, err := os.Open(keystorePath)
	defer file.Close()
	defer b.removeTemporaryKeystore(keystorePath)
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if stat.Size() > MaxKeystoreSize {
		err = fmt.Errorf("keystore is suspiciously large at %d bytes", stat.Size())
		return nil, err
	}
	jsonKeystore, err = ioutil.ReadFile(keystorePath)
	if err != nil {
		return nil, err
	}
	return jsonKeystore, nil

}

func (b *backend) readTrustee(ctx context.Context, req *logical.Request, name string) (*Trustee, error) {
	path := fmt.Sprintf("trustees/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var trustee Trustee
	err = entry.DecodeJSON(&trustee)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize trustee at %s", path)
	}

	return &trustee, nil
}

func (b *backend) contains(stringSlice []string, searchString string) bool {
	for _, value := range stringSlice {
		if value == searchString {
			return true
		}
	}
	return false
}

func contains(stringSlice []string, searchString string) bool {
	for _, value := range stringSlice {
		if value == searchString {
			return true
		}
	}
	return false
}

func dedup(stringSlice []string) []string {
	var returnSlice []string
	for _, value := range stringSlice {
		if !contains(returnSlice, value) {
			returnSlice = append(returnSlice, value)
		}
	}
	return returnSlice
}

func hashKeccak256(data string) []byte {
	input := []byte(data)
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(input), input)
	hash := crypto.Keccak256([]byte(msg))
	return hash
}

// ZeroKey removes the key from memory
func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

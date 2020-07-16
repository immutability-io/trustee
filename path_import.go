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
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/sha3"
)

func importPaths(b *PluginBackend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern:      "import/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Import a single Ethereum JSON keystore. ",
			HelpDescription: `

Reads a JSON keystore, decrypts it and stores the passphrase.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"path": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Path to the keystore file - not the parent directory.",
				},
				"passphrase": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Passphrase used to encrypt private key - will not be returned.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathImportCreate,
			},
		},
	}
}

func (b *PluginBackend) pathImportExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	trusteePath := strings.Replace(req.Path, RequestPathImport, RequestPathTrustees, -1)
	return pathExists(ctx, req, trusteePath)
}

func (b *PluginBackend) pathImportCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	trustee, err := b.readTrustee(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("Error reading trustee")
	}
	if trustee == nil {
		keystorePath := data.Get("path").(string)
		passphrase := data.Get("passphrase").(string)
		privateKey, err := b.importJSONKeystore(ctx, keystorePath, passphrase)
		if err != nil {
			return nil, err
		}
		defer ZeroKey(privateKey)
		privateKeyBytes := crypto.FromECDSA(privateKey)
		privateKeyString := hexutil.Encode(privateKeyBytes)[2:]

		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("error casting public key to ECDSA")
		}

		publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
		publicKeyString := hexutil.Encode(publicKeyBytes)[4:]

		hash := sha3.NewLegacyKeccak256()
		hash.Write(publicKeyBytes[1:])
		address := hexutil.Encode(hash.Sum(nil)[12:])

		trusteeJSON := &Trustee{
			Address:    address,
			PrivateKey: privateKeyString,
			PublicKey:  publicKeyString,
		}
		path := fmt.Sprintf("trustees/%s", name)
		entry, err := logical.StorageEntryJSON(path, trusteeJSON)
		if err != nil {
			return nil, err
		}

		err = req.Storage.Put(ctx, entry)
		if err != nil {
			return nil, err
		}
		b.crossReference(ctx, req, name, trusteeJSON.Address)
		return &logical.Response{
			Data: map[string]interface{}{
				"address": trusteeJSON.Address,
			},
		}, nil
	}

	return nil, fmt.Errorf("account %s exists", name)

}

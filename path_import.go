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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func importPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern:      "import/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Import a single Ethereum JSON keystore. ",
			HelpDescription: `

Reads a JSON keystore, decrypts it and stores the passphrase.

`,
			Fields: map[string]*framework.FieldSchema{
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

func (b *backend) pathImportExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	trusteePath := strings.Replace(req.Path, RequestPathImport, RequestPathTrustees, -1)
	return pathExists(ctx, req, trusteePath)
}

func (b *backend) pathImportCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if validConnection, err := b.validIPConstraints(ctx, req); !validConnection {
		return nil, err
	}
	trusteePath := strings.Replace(req.Path, RequestPathImport, RequestPathTrustees, -1)
	exists, err := pathExists(ctx, req, trusteePath)
	if !exists || err != nil {
		keystorePath := data.Get("path").(string)
		passphrase := data.Get("passphrase").(string)
		address, jsonKeystore, err := b.importJSONKeystore(ctx, keystorePath, passphrase)
		if err != nil {
			return nil, err
		}
		filename := filepath.Base(keystorePath)
		trusteeJSON := &Trustee{Address: address,
			Passphrase:   passphrase,
			KeystoreName: filename,
			JSONKeystore: jsonKeystore}

		entry, err := logical.StorageEntryJSON(trusteePath, trusteeJSON)
		if err != nil {
			return nil, err
		}

		err = req.Storage.Put(ctx, entry)
		if err != nil {
			return nil, err
		}
		return &logical.Response{
			Data: map[string]interface{}{
				"address": address,
			},
		}, nil
	}
	return nil, fmt.Errorf("this path %s exists. You can't import on top of it", trusteePath)

}

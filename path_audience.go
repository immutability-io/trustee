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
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// Audience is a public key known to vault. A Trustee has an address (Ethereum-compatible)
type Audience struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

func audiencesPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "audiences/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathAudiencesList,
			},
			HelpSynopsis: "List all the audiences at a path",
			HelpDescription: `
		All the trustees will be listed.
		`,
		},
		&framework.Path{
			Pattern:      "audiences/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Create an audience using trustee JWT",
			HelpDescription: `

Creates (or updates) an audience.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"token": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Trustee token (JWT).",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathAudiencesRead,
				logical.CreateOperation: b.pathAudiencesCreate,
				logical.DeleteOperation: b.pathAudiencesDelete,
			},
		},
	}
}

func (b *backend) pathAudiencesList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	vals, err := req.Storage.List(ctx, "audiences/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) pathAudiencesCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	rawToken := data.Get("token").(string)
	_, pubkey, err := b.verifyClaim(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	publicKeyBytes := crypto.FromECDSAPub(pubkey)
	publicKey := hex.EncodeToString(publicKeyBytes)
	address := crypto.PubkeyToAddress(*pubkey)

	audienceJSON := &Audience{
		Address:   address.Hex(),
		PublicKey: publicKey,
	}
	entry, err := logical.StorageEntryJSON(req.Path, audienceJSON)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": audienceJSON.Address,
		},
	}, nil
}

func (b *backend) pathAudiencesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	audience, err := b.readAudience(ctx, req, name)
	if err != nil {
		return nil, err
	}

	if audience == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"address": audience.Address,
		},
	}, nil
}

func (b *backend) readAudience(ctx context.Context, req *logical.Request, name string) (*Audience, error) {
	path := fmt.Sprintf("audiences/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var audience Audience
	err = entry.DecodeJSON(&audience)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize audience at %s", path)
	}

	return &audience, nil
}

func (b *backend) pathAudiencesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathEncryptForAudience(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	plaintext := data.Get("plaintext").(string)
	audience, err := b.readAudience(ctx, req, name)
	if err != nil {
		return nil, err
	}
	ciphertext, err := b.encryptForAudience(ctx, audience, plaintext)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext": ciphertext,
		},
	}, nil

}

func (b *backend) encryptForAudience(ctx context.Context, audience *Audience, plaintext string) (string, error) {

	publicKeyBytes, err := hex.DecodeString(audience.PublicKey)
	if err != nil {
		return "", err
	}

	pubKey, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
	if err != nil {
		return "", err
	}

	// Encrypt a message decryptable by the private key corresponding to pubKey
	ciphertextBytes, err := btcec.Encrypt(pubKey, []byte(plaintext))
	if err != nil {
		return "", err
	}
	ciphertext := hexutil.Encode(ciphertextBytes)

	return ciphertext, nil

}

func (b *backend) encryptClaims(ctx context.Context, audience *Audience, claims jwt.MapClaims) (jwt.MapClaims, error) {
	encryptedClaims := make(jwt.MapClaims)
	for key, value := range claims {
		ciphertext, err := b.encryptForAudience(ctx, audience, value.(string))
		if err != nil {
			return nil, err
		}
		encryptedClaims[key] = ciphertext
	}
	return encryptedClaims, nil
}

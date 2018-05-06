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

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/sethvargo/go-diceware/diceware"
)

const (
	// VaultNetwork is a chain_id used to ensure compatibility with Ethereum
	VaultNetwork string = "1977"
)

// Trustee is a trusted entity in vault. A Trustee has an address (Ethereum-compatible)
type Trustee struct {
	Address      string   `json:"address"`
	Passphrase   string   `json:"passphrase"`
	KeystoreName string   `json:"keystore_name"`
	ChainID      string   `json:"chain_id"`
	Whitelist    []string `json:"whitelist"`
	Blacklist    []string `json:"blacklist"`
	JSONKeystore []byte   `json:"json_keystore"`
}

func trusteesPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "trustees/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathTrusteesList,
			},
			HelpSynopsis: "List all the trustees at a path",
			HelpDescription: `
			All the trustees will be listed.
			`,
		},
		&framework.Path{
			Pattern:      "trustees/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Create a trustee using a generated or provided passphrase",
			HelpDescription: `

Creates (or updates) a trustee: an trustee controlled by a private key. Also
creates a Ethereum compatible keystore that is protected by a passphrase that can be supplied or optionally
generated. The generator produces a high-entropy passphrase with the provided length and requirements.
The passphrase is not returned, but it is stored at a separate path (trustees/<name>/passphrase) to allow fine
grained access controls over exposure of the passphrase. The update operation will create a new keystore using
the new passphrase.

`,
			Fields: map[string]*framework.FieldSchema{
				"chain_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The Ethereum network that is being used - for compatibility.",
					Default:     VaultNetwork,
				},
				"whitelist": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "The list of trustees that this trustee trusts.",
				},
				"blacklist": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "The list of trustees that this trustee doesn't trust.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathTrusteesRead,
				logical.CreateOperation: b.pathTrusteesCreate,
				logical.UpdateOperation: b.pathTrusteeUpdate,
				logical.DeleteOperation: b.pathTrusteesDelete,
			},
		},
		&framework.Path{
			Pattern:      "trustees/" + framework.GenericNameRegex("name") + "/export",
			HelpSynopsis: "Export a Ethereum compatible JSON keystore from vault into the provided path.",
			HelpDescription: `

Writes a JSON keystore to a folder (e.g., /Users/immutability/.ethereum/keystore).

`,
			Fields: map[string]*framework.FieldSchema{
				"path": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Directory to export the keystore into - must be an absolute path.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathExportCreate,
			},
		},
		&framework.Path{
			Pattern:      "trustees/" + framework.GenericNameRegex("name") + "/sign",
			HelpSynopsis: "Hash and sign data",
			HelpDescription: `

Hash and sign data using the trustee's private key.

`,
			Fields: map[string]*framework.FieldSchema{
				"data": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The data to hash (keccak) and sign.",
				},
				"raw": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Default:     false,
					Description: "if true, data is expected to be raw hashed transaction data in hex encoding - won't hash prior to signing",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathSign,
			},
		},
		&framework.Path{
			Pattern:      "trustees/" + framework.GenericNameRegex("name") + "/verify",
			HelpSynopsis: "Verify that this trustee signed something.",
			HelpDescription: `

Validate that this trustee signed some data.

`,
			Fields: map[string]*framework.FieldSchema{
				"data": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The data to verify the signature of.",
				},
				"raw": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Default:     false,
					Description: "if true, data is expected to be raw hashed transaction data in hex encoding - won't hash prior to signing",
				},
				"signature": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The signature to verify",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathVerify,
			},
		},
	}
}

func (b *backend) pathTrusteesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	trustee, err := b.readTrustee(ctx, req, req.Path)
	if err != nil {
		return nil, err
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"address":   trustee.Address,
			"chain_id":  trustee.ChainID,
			"whitelist": trustee.Whitelist,
			"blacklist": trustee.Blacklist,
		},
	}, nil
}

func (b *backend) pathTrusteesCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainID := data.Get("chain_id").(string)
	whitelist := data.Get("whitelist").([]string)
	blacklist := data.Get("blacklist").([]string)
	list, _ := diceware.Generate(PassphraseWords)
	passphrase := strings.Join(list, PassphraseSeparator)
	tmpDir, err := b.createTemporaryKeystoreDirectory()
	if err != nil {
		return nil, err
	}
	ks := keystore.NewKeyStore(tmpDir, keystore.StandardScryptN, keystore.StandardScryptP)
	trustee, err := ks.NewAccount(passphrase)
	if err != nil {
		return nil, err
	}
	keystorePath := strings.Replace(trustee.URL.String(), ProtocolKeystore, "", -1)

	jsonKeystore, err := b.readJSONKeystore(keystorePath)
	if err != nil {
		return nil, err
	}
	trusteeJSON := &Trustee{Address: trustee.Address.Hex(),
		ChainID:      chainID,
		Passphrase:   passphrase,
		Whitelist:    dedup(whitelist),
		Blacklist:    dedup(blacklist),
		KeystoreName: filepath.Base(trustee.URL.String()),
		JSONKeystore: jsonKeystore}
	entry, err := logical.StorageEntryJSON(req.Path, trusteeJSON)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}
	b.removeTemporaryKeystore(tmpDir)
	return &logical.Response{
		Data: map[string]interface{}{
			"address":   trusteeJSON.Address,
			"chain_id":  trusteeJSON.ChainID,
			"whitelist": trusteeJSON.Whitelist,
			"blacklist": trusteeJSON.Blacklist,
		},
	}, nil
}

func (b *backend) pathTrusteeUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	whitelist := data.Get("whitelist").([]string)
	blacklist := data.Get("blacklist").([]string)
	trustee, err := b.readTrustee(ctx, req, req.Path)
	if err != nil {
		return nil, err
	}
	trustee.Whitelist = dedup(whitelist)
	trustee.Blacklist = dedup(blacklist)

	entry, _ := logical.StorageEntryJSON(req.Path, trustee)

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address":   trustee.Address,
			"chain_id":  trustee.ChainID,
			"whitelist": trustee.Whitelist,
			"blacklist": trustee.Blacklist,
		},
	}, nil
}

func (b *backend) pathTrusteesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathTrusteesList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, "trustees/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var hash []byte
	if data.Get("raw").(bool) {
		input := data.Get("data").(string)
		var err error
		hash, err = hexutil.Decode(input)
		if err != nil {
			return nil, err
		}
	} else {
		input := []byte(data.Get("data").(string))
		msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(input), input)
		hash = crypto.Keccak256([]byte(msg))
	}

	prunedPath := strings.Replace(req.Path, "/sign", "", -1)
	trustee, err := b.readTrustee(ctx, req, prunedPath)
	if err != nil {
		return nil, err
	}
	key, err := b.getTrusteePrivateKey(prunedPath, *trustee)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key.PrivateKey)
	signature, err := crypto.Sign(hash, key.PrivateKey)

	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hexutil.Encode(signature[:]),
		},
	}, nil
}

func (b *backend) pathVerify(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var hash []byte
	if data.Get("raw").(bool) {
		input := data.Get("data").(string)
		var err error
		hash, err = hexutil.Decode(input)
		if err != nil {
			return nil, err
		}
	} else {
		input := []byte(data.Get("data").(string))
		msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(input), input)
		hash = crypto.Keccak256([]byte(msg))
	}
	signatureRaw := data.Get("signature").(string)

	prunedPath := strings.Replace(req.Path, "/verify", "", -1)
	trustee, err := b.readTrustee(ctx, req, prunedPath)
	if err != nil {
		return nil, err
	}
	signature, err := hexutil.Decode(signatureRaw)

	if err != nil {
		return nil, err
	}
	pubkey, err := crypto.SigToPub(hash, signature)

	if err != nil {
		return nil, err
	}
	address := crypto.PubkeyToAddress(*pubkey)

	verified := trustee.Address == address.Hex()
	return &logical.Response{
		Data: map[string]interface{}{
			"verified": verified,
		},
	}, nil
}

func (b *backend) pathExportCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	directory := data.Get("path").(string)
	prunedPath := strings.Replace(req.Path, "/export", "", -1)
	trustee, err := b.readTrustee(ctx, req, prunedPath)
	if err != nil {
		return nil, err
	}
	list, _ := diceware.Generate(PassphraseWords)
	passphrase := strings.Join(list, PassphraseSeparator)
	tmpDir, err := b.createTemporaryKeystoreDirectory()
	if err != nil {
		return nil, err
	}
	keystorePath, err := b.writeTemporaryKeystoreFile(tmpDir, trustee.KeystoreName, trustee.JSONKeystore)
	if err != nil {
		return nil, err
	}

	jsonKeystore, err := b.rekeyJSONKeystore(keystorePath, trustee.Passphrase, passphrase)
	b.removeTemporaryKeystore(tmpDir)
	if err != nil {
		return nil, err
	}
	trustee.Passphrase = passphrase
	trustee.JSONKeystore = jsonKeystore

	filePath, err := b.exportKeystore(directory, trustee)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"path":       filePath,
			"passphrase": passphrase,
		},
	}, nil
}

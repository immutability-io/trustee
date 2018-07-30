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
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/cidrutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/satori/go.uuid"
	"github.com/sethvargo/go-diceware/diceware"
)

// Trustee is a trusted entity in vault. A Trustee has an address (Ethereum-compatible)
type Trustee struct {
	Address      string `json:"address"`
	Passphrase   string `json:"passphrase"`
	KeystoreName string `json:"keystore_name"`
	JSONKeystore []byte `json:"json_keystore"`
}

// TrusteeName stores the name of the trustee to allow reverse lookup by address
type TrusteeName struct {
	Name string `json:"name"`
}

// TrusteeAddress stores the name of the trustee to allow reverse lookup by address
type TrusteeAddress struct {
	Address string `json:"address"`
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
				"name": &framework.FieldSchema{Type: framework.TypeString},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathTrusteesRead,
				logical.CreateOperation: b.pathTrusteesCreate,
				logical.DeleteOperation: b.pathTrusteesDelete,
			},
		},
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
			Pattern:      "addresses/" + framework.GenericNameRegex("address"),
			HelpSynopsis: "Lookup a trustee's name by address.",
			HelpDescription: `

			Lookup a trustee's name by address.
`,
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathAddressesRead,
			},
		},
		&framework.Path{
			Pattern:      "names/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Lookup a trustee's address by name.",
			HelpDescription: `

			Lookup a trustee's address by name.
`,
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathNamesRead,
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
			Pattern:      "trustees/" + framework.GenericNameRegex("name") + "/claim",
			HelpSynopsis: "Create a JWT containing claims. Sign with trustees ECDSA private key.",
			HelpDescription: `

Create a JWT containing claims. Sign with trustees ECDSA private key.

`,
			Fields: map[string]*framework.FieldSchema{
				"subject": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The Subject of the claims. Identified by `sub` in the JWT.",
				},
				"audience": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The Audience for which these claims are intended. Identified by `aud` in the JWT.",
				},
				"expiry": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "1h",
					Description: "The expiry for this token - this is a duration. This will be used to derive `exp` in the JWT.",
				},
				"not_before_time": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "This token cannot be used before this time (UNIX time format) - defaults to now. Identified by `nbf` in the JWT.",
				},
				"claims": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The claims being asserted. This is a URL encoded JSON blob. (See documentation.)",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathCreateJWT,
			},
		},
	}
}

func (b *backend) pathTrusteesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	trustee, err := b.readTrustee(ctx, req, req.Path)
	if err != nil {
		return nil, err
	}

	if trustee == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"address": trustee.Address,
		},
	}, nil
}

func (b *backend) pathTrusteesCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	trusteeName := strings.Replace(req.Path, "trustees/", "", -1)

	if validConnection, err := b.validIPConstraints(ctx, req); !validConnection {
		return nil, err
	}

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
	trusteeNameJSON := &TrusteeName{Name: trusteeName}
	trusteeAddressJSON := &TrusteeAddress{Address: trustee.Address.Hex()}
	trusteeJSON := &Trustee{Address: trustee.Address.Hex(),
		Passphrase:   passphrase,
		KeystoreName: filepath.Base(trustee.URL.String()),
		JSONKeystore: jsonKeystore}

	pathTrusteeName := fmt.Sprintf("addresses/%s", trustee.Address.Hex())
	pathTrusteeAddress := fmt.Sprintf("names/%s", trusteeName)
	lookupNameEntry, err := logical.StorageEntryJSON(pathTrusteeName, trusteeNameJSON)
	if err != nil {
		return nil, err
	}
	lookupAddressEntry, err := logical.StorageEntryJSON(pathTrusteeAddress, trusteeAddressJSON)
	if err != nil {
		return nil, err
	}
	entry, err := logical.StorageEntryJSON(req.Path, trusteeJSON)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, lookupNameEntry)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, lookupAddressEntry)
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
			"address": trusteeJSON.Address,
		},
	}, nil
}

func (b *backend) pathTrusteesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if validConnection, err := b.validIPConstraints(ctx, req); !validConnection {
		return nil, err
	}
	trusteeName := strings.Replace(req.Path, "trustees/", "", -1)
	trustee, err := b.readTrustee(ctx, req, req.Path)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}
	// Remove lookup value
	pathTrusteeName := fmt.Sprintf("addresses/%s", trustee.Address)
	pathTrusteeAddress := fmt.Sprintf("names/%s", trusteeName)
	if err := req.Storage.Delete(ctx, pathTrusteeName); err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, pathTrusteeAddress); err != nil {
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

func (b *backend) pathExportCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if validConnection, err := b.validIPConstraints(ctx, req); !validConnection {
		return nil, err
	}
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

func (b *backend) pathCreateJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	subject := data.Get("subject").(string)
	audience := data.Get("audience").(string)
	expiry := data.Get("expiry").(string)
	notBeforeTime := data.Get("not_before_time").(string)
	claimsData := data.Get("claims").(string)
	prunedPath := strings.Replace(req.Path, "/claim", "", -1)
	trustee, err := b.readTrustee(ctx, req, prunedPath)
	if err != nil {
		return nil, err
	}
	var claims jwt.MapClaims
	if claimsData != "" {
		if err := json.Unmarshal([]byte(claimsData), &claims); err != nil {
			return nil, err
		}
	} else {
		claims = make(jwt.MapClaims)
	}
	claims["iss"] = trustee.Address
	if audience != "" {
		claims["aud"] = audience
	}
	if subject != "" {
		claims["sub"] = subject
	} else {
		claims["sub"] = trustee.Address
	}
	if notBeforeTime != "" {
		claims["nbf"] = notBeforeTime
	} else {
		claims["nbf"] = fmt.Sprintf("%d", time.Now().UTC().Unix())
	}
	timeUnix, err := strconv.ParseInt(claims["nbf"].(string), 10, 64)
	if err != nil {
		return nil, err
	}
	timeStart := time.Unix(timeUnix, 0)
	timeExpiry, err := time.ParseDuration(expiry)
	if err != nil {
		return nil, err
	}
	claims["exp"] = fmt.Sprintf("%d", timeStart.Add(timeExpiry).Unix())

	key, err := b.getTrusteePrivateKey(*trustee)
	if err != nil {
		return nil, err
	}
	uniqueID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	hash := hashKeccak256(uniqueID.String())
	signature, err := crypto.Sign(hash, key.PrivateKey)

	alg := jwt.GetSigningMethod(JWTAlgorithm)
	if alg == nil {
		return nil, fmt.Errorf("Couldn't find signing method: %s", JWTAlgorithm)
	}
	claims["jti"] = uniqueID.String()
	claims["eth"] = hexutil.Encode(signature[:])
	// create a new JWT
	token := jwt.NewWithClaims(alg, claims)
	tokenOutput, err := token.SignedString(key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Error signing token: %v", err)
	}
	defer zeroKey(key.PrivateKey)
	claims["jwt"] = tokenOutput
	return &logical.Response{
		Data: claims,
	}, nil
}

func (b *backend) validIPConstraints(ctx context.Context, req *logical.Request) (bool, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	if config == nil {
		return true, err
	}
	if len(config.BoundCIDRList) != 0 {
		if req.Connection == nil || req.Connection.RemoteAddr == "" {
			return false, fmt.Errorf("failed to get connection information")
		}

		belongs, err := cidrutil.IPBelongsToCIDRBlocksSlice(req.Connection.RemoteAddr, config.BoundCIDRList)
		if err != nil {
			return false, errwrap.Wrapf("failed to verify the CIDR restrictions set on the role: {{err}}", err)
		}
		if !belongs {
			return false, fmt.Errorf("source address %q unauthorized through CIDR restrictions on the role", req.Connection.RemoteAddr)
		}
	}
	return true, nil
}

// PrettyPrint prints an indented JSON payload. This is used for development debugging.
func PrettyPrint(v interface{}) string {
	jsonString, _ := json.Marshal(v)
	var out bytes.Buffer
	json.Indent(&out, jsonString, "", "  ")
	return out.String()
}

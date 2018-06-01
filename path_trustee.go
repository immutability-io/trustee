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
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	jwt "github.com/immutability-io/jwt-go"
	"github.com/satori/go.uuid"
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
		&framework.Path{
			Pattern:      "verify",
			HelpSynopsis: "Verify that this claim (JWT) is good.",
			HelpDescription: `

Validate that this trustee made a claime.

`,
			Fields: map[string]*framework.FieldSchema{
				"claim": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The JWT to verify.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathVerifyClaim,
			},
		},
	}
}

func (b *backend) pathTrusteesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("pathTrusteesRead")
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
	b.Logger().Info("pathTrusteesCreate")
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
	b.Logger().Info("pathTrusteeUpdate")
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
	b.Logger().Info("pathTrusteesDelete")
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathTrusteesList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("pathTrusteesList")
	vals, err := req.Storage.List(ctx, "trustees/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) pathExportCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("pathExportCreate")
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
	b.Logger().Info("pathCreateJWT")
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

	key, err := b.getTrusteePrivateKey(prunedPath, *trustee)
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

func (b *backend) pathVerifyClaim(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("pathVerifyClaim")
	rawToken := data.Get("claim").(string)
	tokenWithoutWhitespace := regexp.MustCompile(`\s*$`).ReplaceAll([]byte(rawToken), []byte{})
	token := string(tokenWithoutWhitespace)

	jwtToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil || jwtToken == nil {
		b.Logger().Info(fmt.Sprintf("ERROR PARSE\n"))
		return nil, fmt.Errorf("cannot parse token")
	}
	unverifiedJwt := jwtToken.Claims.(jwt.MapClaims)
	if unverifiedJwt == nil {
		return nil, fmt.Errorf("cannot get claims")
	}
	ethereumAddress := unverifiedJwt["iss"].(string)

	jti := unverifiedJwt["jti"].(string)
	signatureRaw := unverifiedJwt["eth"].(string)
	hash := hashKeccak256(jti)
	signature, err := hexutil.Decode(signatureRaw)

	if err != nil {
		return nil, err
	}
	pubkey, err := crypto.SigToPub(hash, signature)

	if err != nil {
		return nil, err
	}
	address := crypto.PubkeyToAddress(*pubkey)

	if ethereumAddress == address.Hex() {
		validateJwt, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			return pubkey, nil
		})
		claims := validateJwt.Claims.(jwt.MapClaims)
		err = claims.Valid()
		if err != nil {
			return nil, err
		}
		return &logical.Response{
			Data: claims,
		}, nil
	}
	return nil, fmt.Errorf("Error verifying token")
}

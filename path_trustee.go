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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/scrypt"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pborman/uuid"
	"github.com/sethvargo/go-diceware/diceware"
)

// Trustee is a trusted entity in vault. A Trustee has an address (Ethereum-compatible)
type Trustee struct {
	Address    string `json:"address"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"` // Ethereum public key derived from the private key
}

// TrusteeName stores the name of the trustee to allow reverse lookup by address
type TrusteeName struct {
	Name string `json:"name"`
}

// TrusteeAddress stores the name of the trustee to allow reverse lookup by address
type TrusteeAddress struct {
	Address string `json:"address"`
}
type cipherparamsJSON struct {
	IV string `json:"iv"`
}

const (
	version = 3
)

type encryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	ID      string     `json:"id"`
	Version int        `json:"version"`
}

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

const (
	keyHeaderKDF = "scrypt"

	scryptR     = 8
	scryptDKLen = 32
)

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
				"name": &framework.FieldSchema{Type: framework.TypeString},
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
			Pattern:      "trustees/" + framework.GenericNameRegex("name") + "/encrypt",
			HelpSynopsis: "Encrypt a base64 encoded string with the trustee public key.",
			HelpDescription: `

Encrypt a base64 encoded string with the trustee public key.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"plaintext": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Base64 encoded string.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathEncrypt,
			},
		},
		&framework.Path{
			Pattern:      "trustees/" + framework.GenericNameRegex("name") + "/decrypt",
			HelpSynopsis: "Decrypt with the trustee private key.",
			HelpDescription: `

Decrypt with the trustee private key.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"ciphertext": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Encrypted string.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathDecrypt,
			},
		},
		&framework.Path{
			Pattern:      "trustees/" + framework.GenericNameRegex("name") + "/claim",
			HelpSynopsis: "Create a JWT containing claims. Sign with trustees ECDSA private key.",
			HelpDescription: `

Create a JWT containing claims. Sign with trustees ECDSA private key.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"subject": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The Subject of the claims. Identified by `sub` in the JWT.",
				},
				"audience": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The Audience for which these claims are intended. Identified by `aud` in the JWT.",
				},
				"encrypt": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Default:     false,
					Description: "If `true` the claims will be encrypted using the `audience` public key.",
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
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	trustee, err := b.readTrustee(ctx, req, name)
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
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	privateKey, err := crypto.GenerateKey()
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

	hash := sha3.NewKeccak256()
	hash.Write(publicKeyBytes[1:])
	address := hexutil.Encode(hash.Sum(nil)[12:])

	trusteeJSON := &Trustee{
		Address:    address,
		PrivateKey: privateKeyString,
		PublicKey:  publicKeyString,
	}
	entry, err := logical.StorageEntryJSON(req.Path, trusteeJSON)
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

func (b *backend) pathTrusteesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	trustee, err := b.readTrustee(ctx, req, name)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}
	// Remove lookup value
	pathTrusteeName := fmt.Sprintf("addresses/%s", trustee.Address)
	pathTrusteeAddress := fmt.Sprintf("names/%s", name)
	if err := req.Storage.Delete(ctx, pathTrusteeName); err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, pathTrusteeAddress); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathTrusteesList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	vals, err := req.Storage.List(ctx, "trustees/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) pathExportCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	id := uuid.NewRandom()
	name := data.Get("name").(string)
	trustee, err := b.readTrustee(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("Error reading account")
	}
	if trustee == nil {
		return nil, nil
	}
	keystorePath := data.Get("path").(string)
	privateKey, err := crypto.HexToECDSA(trustee.PrivateKey)
	if err != nil {
		return nil, err
	}
	defer ZeroKey(privateKey)

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	list, _ := diceware.Generate(PassphraseWords)
	passphrase := strings.Join(list, PassphraseSeparator)
	jsonBytes, err := encryptKey(privateKey, &address, id, passphrase, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(keystorePath, keyFileName(address))

	writeKeyFile(path, jsonBytes)
	return &logical.Response{
		Data: map[string]interface{}{
			"path":       path,
			"passphrase": passphrase,
		},
	}, nil
}

func (b *backend) pathCreateJWT(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	trustee, err := b.readTrustee(ctx, req, name)
	if err != nil {
		return nil, err
	}
	var audience *Audience
	subject := data.Get("subject").(string)
	audienceName := data.Get("audience").(string)
	encrypt := data.Get("encrypt").(bool)
	expiry := data.Get("expiry").(string)
	notBeforeTime := data.Get("not_before_time").(string)
	claimsData := data.Get("claims").(string)
	var claims jwt.MapClaims
	if claimsData != "" {
		if err := json.Unmarshal([]byte(claimsData), &claims); err != nil {
			return nil, err
		}
	} else {
		claims = make(jwt.MapClaims)
	}
	if encrypt {
		audience, err = b.readAudience(ctx, req, audienceName)
		if audience == nil || err != nil {
			return nil, fmt.Errorf("audience not found - cannot encrypt")
		}
		claims, err = b.encryptClaims(ctx, audience, claims)
		if err != nil {
			return nil, err
		}
	}
	claims["iss"] = trustee.Address
	if audience != nil {
		claims["aud"] = audience.Address
	} else if audienceName != "" {
		claims["aud"] = audienceName
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

	uniqueID := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	hash := hashKeccak256(uniqueID.String())
	privateKey, err := crypto.HexToECDSA(trustee.PrivateKey)
	if err != nil {
		return nil, err
	}
	defer ZeroKey(privateKey)
	signature, err := crypto.Sign(hash, privateKey)

	alg := jwt.GetSigningMethod(JWTAlgorithm)
	if alg == nil {
		return nil, fmt.Errorf("Couldn't find signing method: %s", JWTAlgorithm)
	}
	claims["jti"] = uniqueID.String()
	claims["eth"] = hexutil.Encode(signature[:])
	// create a new JWT
	token := jwt.NewWithClaims(alg, claims)
	tokenOutput, err := token.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("Error signing token: %v", err)
	}
	defer ZeroKey(privateKey)
	claims["jwt"] = tokenOutput
	return &logical.Response{
		Data: claims,
	}, nil
}

// PrettyPrint prints an indented JSON payload. This is used for development debugging.
func PrettyPrint(v interface{}) string {
	jsonString, _ := json.Marshal(v)
	var out bytes.Buffer
	json.Indent(&out, jsonString, "", "  ")
	return out.String()
}

func (b *backend) verifySignature(ctx context.Context, req *logical.Request, data *framework.FieldData, name string) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	trustee, err := b.readTrustee(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading account")
	}
	if trustee == nil {
		return nil, nil
	}
	signature := data.Get("signature").(string)
	dataToSign := data.Get("data").(string)
	privateKey, err := crypto.HexToECDSA(trustee.PrivateKey)
	if err != nil {
		return nil, err
	}
	defer ZeroKey(privateKey)
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	dataBytes := []byte(dataToSign)
	signatureBytes, err := hexutil.Decode(signature)
	if err != nil {
		return nil, err
	}
	hash := crypto.Keccak256Hash(dataBytes)

	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), signatureBytes)
	if err != nil {
		return nil, err
	}

	matches := bytes.Equal(sigPublicKey, publicKeyBytes)
	if !matches {
		return nil, fmt.Errorf("signature not verified")
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"verified":  matches,
			"signature": signature,
			"address":   trustee.Address,
		},
	}, nil

}

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

func encryptKey(key *ecdsa.PrivateKey, address *common.Address, id uuid.UUID, auth string, scryptN, scryptP int) ([]byte, error) {
	authArray := []byte(auth)

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return nil, err
	}
	encryptKey := derivedKey[:16]
	keyBytes := math.PaddedBigBytes(key.D, 32)

	iv := make([]byte, aes.BlockSize) // 16
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	cipherText, err := aesCTRXOR(encryptKey, keyBytes, iv)
	if err != nil {
		return nil, err
	}
	mac := crypto.Keccak256(derivedKey[16:32], cipherText)

	scryptParamsJSON := make(map[string]interface{}, 5)
	scryptParamsJSON["n"] = scryptN
	scryptParamsJSON["r"] = scryptR
	scryptParamsJSON["p"] = scryptP
	scryptParamsJSON["dklen"] = scryptDKLen
	scryptParamsJSON["salt"] = hex.EncodeToString(salt)

	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	cryptoStruct := cryptoJSON{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          keyHeaderKDF,
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
	}
	encryptedKeyJSONV3 := encryptedKeyJSONV3{
		hex.EncodeToString(address[:]),
		cryptoStruct,
		id.String(),
		version,
	}
	return json.Marshal(encryptedKeyJSONV3)
}

func writeKeyFile(file string, content []byte) error {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	f.Close()
	return os.Rename(f.Name(), file)
}

func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}

func (b *backend) pathEncrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	trustee, err := b.readTrustee(ctx, req, name)
	if err != nil {
		return nil, err
	}
	plaintext := data.Get("plaintext").(string)

	privateKey, err := crypto.HexToECDSA(trustee.PrivateKey)
	if err != nil {
		return nil, err
	}
	defer ZeroKey(privateKey)

	publicKeyBytes := crypto.FromECDSAPub(&privateKey.PublicKey)

	pubKey, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
	if err != nil {
		return nil, err
	}

	// Encrypt a message decryptable by the private key corresponding to pubKey
	ciphertextBytes, err := btcec.Encrypt(pubKey, []byte(plaintext))
	if err != nil {
		return nil, err
	}
	ciphertext := hexutil.Encode(ciphertextBytes)

	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext": ciphertext,
		},
	}, nil

}

func (b *backend) pathDecrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	trustee, err := b.readTrustee(ctx, req, name)
	if err != nil {
		return nil, err
	}
	ciphertext := data.Get("ciphertext").(string)

	// Decode the hex-encoded private key.
	pkBytes, err := hex.DecodeString(trustee.PrivateKey)
	if err != nil {
		return nil, err
	}
	// note that we already have corresponding pubKey
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes)
	ciphertextBytes, err := hexutil.Decode(ciphertext)
	// Try decrypting and verify if it's the same message.
	plaintext, err := btcec.Decrypt(privKey, ciphertextBytes)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": string(plaintext),
		},
	}, nil
}

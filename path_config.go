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

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/cidrutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type config struct {
	BoundCIDRList []string `json:"bound_cidr_list_list" structs:"bound_cidr_list" mapstructure:"bound_cidr_list"`
}

func configPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "config",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathWriteConfig,
				logical.UpdateOperation: b.pathWriteConfig,
				logical.ReadOperation:   b.pathReadConfig,
			},
			HelpSynopsis: "Configure the trustee plugin.",
			HelpDescription: `
			Configure the trustee plugin.
			`,
			Fields: map[string]*framework.FieldSchema{
				"bound_cidr_list": &framework.FieldSchema{
					Type: framework.TypeCommaStringSlice,
					Description: `Comma separated string or list of CIDR blocks. If set, specifies the blocks of
IP addresses which can perform the login operation.`,
				},
			},
		},
	}
}

func (b *backend) pathWriteConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var boundCIDRList []string
	if boundCIDRListRaw, ok := data.GetOk("bound_cidr_list"); ok {
		boundCIDRList = boundCIDRListRaw.([]string)
	}
	configBundle := config{
		BoundCIDRList: boundCIDRList,
	}
	entry, err := logical.StorageEntryJSON("config", configBundle)

	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_cidr_list": configBundle.BoundCIDRList,
		},
	}, nil
}

func (b *backend) pathReadConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configBundle, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if configBundle == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_cidr_list": configBundle.BoundCIDRList,
		},
	}, nil
}

// Config returns the configuration for this backend.
func (b *backend) readConfig(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("the trustee backend is not configured properly")
	}

	var result config
	if entry != nil {
		if err := entry.DecodeJSON(&result); err != nil {
			return nil, fmt.Errorf("error reading configuration: %s", err)
		}
	}

	return &result, nil
}

func (b *backend) configured(ctx context.Context, req *logical.Request) (*config, error) {
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if validConnection, err := b.validIPConstraints(config, req); !validConnection {
		return nil, err
	}

	return config, nil
}

func (b *backend) validIPConstraints(config *config, req *logical.Request) (bool, error) {
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

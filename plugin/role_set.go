package gcpsecrets

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/iam/v1"
)

const (
	serviceAccountMaxLen          = 30
	serviceAccountDisplayNameTmpl = "Service account for Vault secrets backend role set %s"
	serviceAccountEmailTemplate   = "%s@%s.iam.gserviceaccount.com"
)

type RoleSet struct {
	Name       string
	SecretType string

	RawBindings string
	Bindings    ResourceBindings

	AccountId *gcputil.ServiceAccountId
	TokenGen  *TokenGenerator
}

func (rs *RoleSet) validate() error {
	var err *multierror.Error
	if rs.Name == "" {
		err = multierror.Append(err, errors.New("role set name is empty"))
	}

	if rs.SecretType == "" {
		err = multierror.Append(err, errors.New("role set secret type is empty"))
	}

	if rs.AccountId == nil {
		err = multierror.Append(err, fmt.Errorf("role set should have account associated"))
	}

	if len(rs.Bindings) == 0 {
		err = multierror.Append(err, fmt.Errorf("role set bindings cannot be empty"))
	}

	if len(rs.RawBindings) == 0 {
		err = multierror.Append(err, fmt.Errorf("role set raw bindings cannot be empty string"))
	}

	switch rs.SecretType {
	case SecretTypeAccessToken:
		if rs.TokenGen == nil {
			err = multierror.Append(err, fmt.Errorf("access token role set should have initialized token generator"))
		} else if len(rs.TokenGen.Scopes) == 0 {
			err = multierror.Append(err, fmt.Errorf("access token role set should have defined scopes"))
		}
	case SecretTypeKey:
		break
	default:
		err = multierror.Append(err, fmt.Errorf("unknown secret type: %s", rs.SecretType))
	}
	return err.ErrorOrNil()
}

func (rs *RoleSet) save(ctx context.Context, s logical.Storage) error {
	if err := rs.validate(); err != nil {
		return err
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolesetStoragePrefix, rs.Name), rs)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (rs *RoleSet) bindingHash() string {
	return getStringHash(rs.RawBindings)
}

func (rs *RoleSet) getServiceAccount(iamAdmin *iam.Service) (*iam.ServiceAccount, error) {
	if rs.AccountId == nil {
		return nil, fmt.Errorf("role set '%s' is invalid, has no associated service account", rs.Name)
	}

	account, err := iamAdmin.Projects.ServiceAccounts.Get(rs.AccountId.ResourceName()).Do()
	if err != nil {
		return nil, fmt.Errorf("could not find service account: %v. If account was deleted, role set must be updated (write to roleset/%s/rotate) before generating new secrets", err, rs.Name)
	} else if account == nil {
		return nil, fmt.Errorf("roleset service account was removed - role set must be updated (path roleset/%s/rotate) before generating new secrets", rs.Name)
	}

	return account, nil
}

type ResourceBindings map[string]util.StringSet

func (rb ResourceBindings) asOutput() map[string][]string {
	out := make(map[string][]string)
	for k, v := range rb {
		out[k] = v.ToSlice()
	}
	return out
}

type TokenGenerator struct {
	KeyName    string
	B64KeyJSON string

	Scopes []string
}

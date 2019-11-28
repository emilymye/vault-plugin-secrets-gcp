package gcpsecrets

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (a *StaticAccount) boundResources() *gcpAccountResources {
	return &gcpAccountResources{
		accountId: a.ServiceAccountId,
		bindings:  a.Bindings,
		tokenGen:  a.TokenGen,
	}
}

func (a *StaticAccount) bindingHash() string {
	return getStringHash(a.RawBindings)
}

type StaticAccount struct {
	Name        string
	SecretType  string
	RawBindings string
	Bindings    ResourceBindings
	gcputil.ServiceAccountId

	TokenGen *TokenGenerator
}

func (a *StaticAccount) validate() error {
	err := &multierror.Error{}
	if a.Name == "" {
		err = multierror.Append(err, errors.New("static account name is empty"))
	}

	if a.SecretType == "" {
		err = multierror.Append(err, errors.New("static account secret type is empty"))
	}

	if a.EmailOrId == "" {
		err = multierror.Append(err, fmt.Errorf("static account must have service account email"))
	}

	switch a.SecretType {
	case SecretTypeAccessToken:
		if a.TokenGen == nil {
			err = multierror.Append(err, fmt.Errorf("access token static account should have initialized token generator"))
		} else if len(a.TokenGen.Scopes) == 0 {
			err = multierror.Append(err, fmt.Errorf("access token static account should have defined scopes"))
		}
	case SecretTypeKey:
		break
	default:
		err = multierror.Append(err, fmt.Errorf("unknown secret type: %s", a.SecretType))
	}
	return err.ErrorOrNil()
}

func (a *StaticAccount) save(ctx context.Context, s logical.Storage) error {
	if err := a.validate(); err != nil {
		return err
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", staticAccountStoragePrefix, a.Name), a)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

// addWalsForRoleSetResources creates WALs to clean up a roleset's service account, bindings, and a key if needed.
func (b *backend) addWalsForStaticAccountResources(ctx context.Context, req *logical.Request, staticAcctName string, boundResources *gcpAccountResources) (walIds []string, err error) {
	if boundResources == nil {
		b.Logger().Debug("skip WALs for nil GCP account resources")
		return nil, nil
	}

	walIds = make([]string, 0, len(boundResources.bindings)+1)
	for resName, roles := range boundResources.bindings {
		walId, err := framework.PutWAL(ctx, req.Storage, walTypeIamPolicy, &walIamPolicy{
			StaticAccount: staticAcctName,
			AccountId:     boundResources.accountId,
			Resource:      resName,
			Roles:         roles.ToSlice(),
		})
		if err != nil {
			return walIds, errwrap.Wrapf("unable to create WAL entry to clean up service account bindings: {{err}}", err)
		}
		walIds = append(walIds, walId)
	}

	if boundResources.tokenGen != nil {
		walId, err := b.addWalStaticAccountServiceAccountKey(ctx, req, staticAcctName, &boundResources.accountId, boundResources.tokenGen.KeyName)
		if err != nil {
			return walIds, err
		}
		walIds = append(walIds, walId)
	}
	return walIds, nil
}

// addWalRoleSetServiceAccountKey creates WAL to clean up a service account key (for access tokens) if needed.
func (b *backend) addWalStaticAccountServiceAccountKey(ctx context.Context, req *logical.Request, acct string, accountId *gcputil.ServiceAccountId, keyName string) (string, error) {
	if accountId == nil {
		return "", fmt.Errorf("given nil account ID for WAL for roleset service account key")
	}

	b.Logger().Debug("add WAL for service account key", "account", accountId.ResourceName(), "keyName", keyName)

	walId, err := framework.PutWAL(ctx, req.Storage, walTypeAccount, &walAccountKey{
		StaticAccount:      acct,
		ServiceAccountName: accountId.ResourceName(),
		KeyName:            keyName,
	})
	if err != nil {
		return "", errwrap.Wrapf("unable to create WAL entry to clean up service account key: {{err}}", err)
	}
	return walId, nil
}

func (b *backend) tryDeleteStaticAccountResources(ctx context.Context, req *logical.Request, boundResources *gcpAccountResources, walIds []string) []string {
	return b.tryDeleteGcpAccountResources(ctx, req, boundResources, flagMustKeepServiceAccount, walIds)
}

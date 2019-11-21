package gcpsecrets

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/sdk/helper/useragent"
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

// saveRoleSetWithNewTokenKey rotates the role set service account, including its name and any keys or bindings
// associated with it.
func (b *backend) saveRoleSetWithNewAccount(ctx context.Context, req *logical.Request, rs *RoleSet, project string, newBinds ResourceBindings, scopes []string) (warning []string, err error) {
	b.Logger().Debug("updating roleset with new account")

	oldResources := rs.boundResources()

	// Generate name for new account
	newSaName := generateAccountNameForRoleSet(rs.Name)

	// Construct IDs for new resources.
	// The actual GCP resources are not created yet, but we need the IDs to create WAL entries.
	newAccountId := &gcputil.ServiceAccountId{
		Project:   project,
		EmailOrId: emailForServiceAccountName(project, newSaName),
	}
	newResources := &roleSetResources{
		rolesetName: rs.Name,
		accountId:   newAccountId,
		bindings:    newBinds,
	}
	if len(scopes) > 0 {
		newResources.tokenGen = &TokenGenerator{Scopes: scopes}
	}

	// Add WALs for both old and new resources.
	// WAL callback checks whether resources are still being used by roleset so
	// there is no harm in adding WALs early, or adding WALs for resources that
	// will eventually get cleaned up.
	b.Logger().Debug("adding WALs for old roleset resources")
	if err := b.addWalsForRoleSetResources(ctx, req, oldResources); err != nil {
		return nil, err
	}

	b.Logger().Debug("adding WALs for new roleset resources")
	if err := b.addWalsForRoleSetResources(ctx, req, newResources); err != nil {
		return nil, err
	}

	// Created new RoleSet resources
	createdResources, err := b.createNewRoleSetResources(ctx, req, rs.Name, newSaName, newResources)
	if err != nil {
		return nil, err
	}

	// Edit roleset with new resources and save to storage.
	rs.AccountId = createdResources.accountId
	rs.Bindings = createdResources.bindings
	rs.TokenGen = createdResources.tokenGen
	if err := rs.save(ctx, req.Storage); err != nil {
		return nil, err
	}

	warnings := b.tryDeleteRoleSetResources(ctx, req, oldResources)
	return warnings, nil
}

// saveRoleSetWithNewTokenKey rotates the role set access_token key and saves it to storage.
func (b *backend) saveRoleSetWithNewTokenKey(ctx context.Context, req *logical.Request, rs *RoleSet, scopes []string) (warning string, err error) {
	b.Logger().Debug("updating roleset with new account key")

	if rs.SecretType != SecretTypeAccessToken {
		return "", fmt.Errorf("a key is not saved or used for non-access-token role set '%s'", rs.Name)
	}

	iamAdmin, err := b.IAMAdminClient(req.Storage)
	if err != nil {
		return "", err
	}

	if rs.AccountId == nil {
		return "", fmt.Errorf("unable to save roleset with new key - account ID was nil")
	}

	oldTokenGen := rs.TokenGen

	// Add WALs for TokenGen - since we don't have a key ID yet, give an empty key name so WAL
	// will know to just clear keys that aren't being used. This also covers up cleaning up
	// the old token generator, so we don't add a separate WAL for that.
	if err := b.addServiceAccountKeyWal(ctx, req, rs.Name, rs.AccountId, ""); err != nil {
		return "", err
	}

	newTokenGen, err := b.createNewTokenGen(ctx, req, rs.AccountId.ResourceName(), scopes)
	if err != nil {
		return "", err
	}

	// Edit roleset with new key and save to storage.
	rs.TokenGen = newTokenGen
	if err := rs.save(ctx, req.Storage); err != nil {
		return "", err
	}

	// Try deleting the old key.
	if err := b.deleteTokenGenKey(ctx, iamAdmin, oldTokenGen); err != nil {
		return errwrap.Wrapf("roleset update succeeded but got error while trying to delete old key - will be cleaned up later by WAL: {{err}}", err).Error(), nil
	}
	return "", nil
}

func (b *backend) createNewRoleSetResources(ctx context.Context, req *logical.Request, rolesetName string, serviceAccountName string, newResources *roleSetResources) (*roleSetResources, error) {
	if newResources == nil || newResources.accountId == nil {
		return nil, fmt.Errorf("plugin error - expected non-nil rolesetResources with valid account id")
	}

	iamAdmin, err := b.IAMAdminClient(req.Storage)
	if err != nil {
		return nil, err
	}

	project := newResources.accountId.Project
	createSaReq := &iam.CreateServiceAccountRequest{
		AccountId:      serviceAccountName,
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: fmt.Sprintf(serviceAccountDisplayNameTmpl, rolesetName),
		},
	}

	// Create new service account
	b.Logger().Debug("creating service account",
		"project", newResources.accountId.Project,
		"request", createSaReq)

	sa, err := iamAdmin.Projects.ServiceAccounts.Create(fmt.Sprintf("projects/%s", project), createSaReq).Do()
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf(
			"unable to create new service account %q: {{err}}",
			newResources.accountId.ResourceName()), err)
	}

	// Create new IAM bindings.
	b.Logger().Debug("creating IAM bindings", "account_email", sa.Email)
	if err := b.createIamBindings(ctx, req, sa.Email, newResources.bindings); err != nil {
		return nil, err
	}

	// Create new token gen if a stubbed tokenGenerator (with scopes) is given.
	if newResources.tokenGen != nil && len(newResources.tokenGen.Scopes) > 0 {
		b.Logger().Debug("creating new TokenGenerator (service account key)",
			"account", sa.Name,
			"scopes", newResources.tokenGen.Scopes)
		tokenGen, err := b.createNewTokenGen(ctx, req, sa.Name, newResources.tokenGen.Scopes)
		if err != nil {
			return nil, err
		}
		newResources.tokenGen = tokenGen
	}

	return newResources, nil
}

func (b *backend) createNewTokenGen(ctx context.Context, req *logical.Request, parent string, scopes []string) (*TokenGenerator, error) {
	iamAdmin, err := b.IAMAdminClient(req.Storage)
	if err != nil {
		return nil, err
	}

	key, err := iamAdmin.Projects.ServiceAccounts.Keys.Create(
		parent,
		&iam.CreateServiceAccountKeyRequest{
			PrivateKeyType: privateKeyTypeJson,
		}).Do()
	if err != nil {
		return nil, err
	}
	return &TokenGenerator{
		KeyName:    key.Name,
		B64KeyJSON: key.PrivateKeyData,
		Scopes:     scopes,
	}, nil
}

func (b *backend) createIamBindings(ctx context.Context, req *logical.Request, saEmail string, binds ResourceBindings) error {
	httpC, err := b.HTTPClient(req.Storage)
	if err != nil {
		return err
	}
	iamHandle := iamutil.GetIamHandle(httpC, useragent.String())

	for resourceName, roles := range binds {
		b.Logger().Debug("setting IAM binding", "resource", resourceName, "roles", roles)
		resource, err := b.iamResources.Parse(resourceName)
		if err != nil {
			return err
		}

		b.Logger().Debug("getting IAM policy for resource name", "name", resourceName)
		p, err := iamHandle.GetIamPolicy(ctx, resource)
		if err != nil {
			return nil
		}

		b.Logger().Debug("got IAM policy for resource name", "name", resourceName)
		changed, newP := p.AddBindings(&iamutil.PolicyDelta{
			Roles: roles,
			Email: saEmail,
		})
		if !changed || newP == nil {
			continue
		}

		b.Logger().Debug("setting IAM policy for resource name", "name", resourceName)
		if _, err := iamHandle.SetIamPolicy(ctx, resource, newP); err != nil {
			return errwrap.Wrapf(fmt.Sprintf("unable to set IAM policy for resource %q: {{err}}", resourceName), err)
		}
	}

	return nil
}

package gcpsecrets

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/iamutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"regexp"
	"time"
)

// roleSetResources is a wrapper around a roleset's managed GCP service account, IAM bindings, and/or keys.
// It exists separately from roleset to allow for construction with or without a roleset (i.e. for deleting
// accounts removed from a RoleSet), and because changing RoleSet requires migration of stored RoleSets.
// A utility for creating roleSetResources from a RoleSet is provided below.
type roleSetResources struct {
	rolesetName string

	accountId *gcputil.ServiceAccountId
	bindings  ResourceBindings
	tokenGen  *TokenGenerator
}

func (rs *RoleSet) boundResources() *roleSetResources {
	if rs.AccountId == nil {
		return nil
	}
	return &roleSetResources{
		accountId:   rs.AccountId,
		rolesetName: rs.Name,
		bindings:    rs.Bindings,
		tokenGen:    rs.TokenGen,
	}
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

// addWalsForRoleSetResources creates WALs to clean up a roleset's service account, bindings, and a key if needed.
func (b *backend) addWalsForRoleSetResources(ctx context.Context, req *logical.Request, boundResources *roleSetResources) error {
	if boundResources == nil {
		b.Logger().Debug("skip WALs for nil roleset resources")
		return nil
	}

	_, err := framework.PutWAL(ctx, req.Storage, walTypeAccount, &walAccount{
		RoleSet: boundResources.rolesetName,
		Id:      *boundResources.accountId,
	})
	if err != nil {
		return errwrap.Wrapf("unable to create WAL entry to clean up service account: {{err}}", err)
	}

	for resName, roleSet := range boundResources.bindings {
		_, err := framework.PutWAL(ctx, req.Storage, walTypeIamPolicy, &walIamPolicy{
			RoleSet:   boundResources.rolesetName,
			AccountId: *boundResources.accountId,
			Resource:  resName,
			Roles:     roleSet.ToSlice(),
		})
		if err != nil {
			return errwrap.Wrapf("unable to create WAL entry to clean up service account bindings: {{err}}", err)
		}
	}

	if boundResources.tokenGen != nil {
		return b.addServiceAccountKeyWal(ctx, req, boundResources.rolesetName, boundResources.accountId, boundResources.tokenGen.KeyName)
	}
	return nil
}

// addServiceAccountKeyWal creates WAL to clean up a roleset service account key (for access tokens) if needed.
func (b *backend) addServiceAccountKeyWal(ctx context.Context, req *logical.Request, rolesetName string, accountId *gcputil.ServiceAccountId, keyName string) error {
	if accountId == nil {
		b.Logger().Debug("skip adding service account key WAL for nil account")
		return nil
	}

	_, err := framework.PutWAL(ctx, req.Storage, walTypeAccount, &walAccountKey{
		RoleSet:            rolesetName,
		ServiceAccountName: accountId.ResourceName(),
		KeyName:            keyName,
	})
	if err != nil {
		return errwrap.Wrapf("unable to create WAL entry to clean up service account key: {{err}}", err)
	}
	return nil
}

// tryDeleteRoleSetResources tries to delete GCP resources previously managed by a roleset.
// This assumes that deletion of these resources will already be guaranteed by WALs and will return errors
// as a list of warnings instead.
func (b *backend) tryDeleteRoleSetResources(ctx context.Context, req *logical.Request, boundResources *roleSetResources) []string {
	if boundResources == nil {
		b.Logger().Debug("skip deletion for nil roleset resources")
		return nil
	}

	httpC, err := b.HTTPClient(req.Storage)
	if err != nil {
		return []string{err.Error()}
	}

	iamAdmin, err := iam.NewService(ctx, option.WithHTTPClient(httpC))
	if err != nil {
		return []string{err.Error()}
	}

	iamHandle := iamutil.GetIamHandle(httpC, useragent.String())

	warnings := make([]string, 0)
	if boundResources.accountId != nil {
		if err := b.deleteTokenGenKey(ctx, iamAdmin, boundResources.tokenGen); err != nil {
			w := fmt.Sprintf("unable to delete key under service account %q (WAL entry to clean-up later has been added): %v", boundResources.accountId.ResourceName(), err)
			warnings = append(warnings, w)
		}

		if err := b.deleteServiceAccount(ctx, iamAdmin, boundResources.accountId); err != nil {
			w := fmt.Sprintf("unable to delete service account %q (WAL entry to clean-up later has been added): %v", boundResources.accountId.ResourceName(), err)
			warnings = append(warnings, w)
		}

		if merr := b.removeBindings(ctx, iamHandle, boundResources.accountId.EmailOrId, boundResources.bindings); merr != nil {
			for _, err := range merr.Errors {
				w := fmt.Sprintf("unable to delete IAM policy bindings for service account %q (WAL entry to clean-up later has been added): %v", boundResources.accountId.EmailOrId, err)
				warnings = append(warnings, w)
			}
		}
	}

	return nil
}

func emailForServiceAccountName(project, accountName string) string {
	return fmt.Sprintf(serviceAccountEmailTemplate, accountName, project)
}

func generateAccountNameForRoleSet(rsName string) (name string) {
	// Sanitize role name
	reg := regexp.MustCompile("[^a-zA-Z0-9-]+")
	rsName = reg.ReplaceAllString(rsName, "-")

	intSuffix := fmt.Sprintf("%d", time.Now().Unix())
	fullName := fmt.Sprintf("vault%s-%s", rsName, intSuffix)
	name = fullName
	if len(fullName) > serviceAccountMaxLen {
		toTrunc := len(fullName) - serviceAccountMaxLen
		name = fmt.Sprintf("vault%s-%s", rsName[:len(rsName)-toTrunc], intSuffix)
	}
	return name
}

func getStringHash(bindingsRaw string) string {
	ssum := sha256.Sum256([]byte(bindingsRaw)[:])
	return base64.StdEncoding.EncodeToString(ssum[:])
}

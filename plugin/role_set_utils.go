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

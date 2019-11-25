package gcpsecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRoleSetRotateAccount(b *backend) *framework.Path {
	return &framework.Path{
		// Path to rotate role set service accounts
		Pattern: fmt.Sprintf("roleset/%s/rotate", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
		},
		ExistenceCheck: b.pathRoleSetExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleSetRotateAccount,
			},
		},
		HelpSynopsis:    pathRoleSetRotateAccountHelpSyn,
		HelpDescription: pathRoleSetRotateAccountHelpDesc,
	}
}

func (b *backend) pathRoleSetRotateAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	b.rolesetLock.Lock()
	defer b.rolesetLock.Unlock()

	rs, err := getRoleSet(name, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if rs == nil {
		return logical.ErrorResponse("roleset '%s' not found", name), nil
	}

	var scopes []string
	if rs.TokenGen != nil {
		scopes = rs.TokenGen.Scopes
	}

	warnings, err := b.saveRoleSetWithNewAccount(ctx, req, rs, rs.AccountId.Project, rs.Bindings, scopes)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	} else if warnings != nil && len(warnings) > 0 {
		return &logical.Response{Warnings: warnings}, nil
	}
	return nil, nil
}

const pathRoleSetRotateAccountHelpSyn = `Rotates or recreates the service account bound to a roleset.`
const pathRoleSetRotateAccountHelpDesc = `
This path allows you to rotate (i.e. recreate) the service account used to
generate secrets for a given role set. This will delete and recreate
the service account, invalidating any old keys/credentials
generated previously.
`

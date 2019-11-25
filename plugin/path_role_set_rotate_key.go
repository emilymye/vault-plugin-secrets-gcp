package gcpsecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRoleSetRotateKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("roleset/%s/rotate-key", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
		},
		ExistenceCheck: b.pathRoleSetExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleSetRotateKey,
			},
		},
		HelpSynopsis:    pathRoleSetRotateKeyHelpSyn,
		HelpDescription: pathRoleSetRotateKeyHelpDesc,
	}
}

func (b *backend) pathRoleSetRotateKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	if rs.SecretType != SecretTypeAccessToken {
		return logical.ErrorResponse("cannot rotate key for non-access-token role set"), nil
	}
	var scopes []string
	if rs.TokenGen != nil {
		scopes = rs.TokenGen.Scopes
	}
	warn, err := b.saveRoleSetWithNewTokenKey(ctx, req, rs, scopes)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if warn != "" {
		return &logical.Response{Warnings: []string{warn}}, nil
	}
	return nil, nil
}

const pathRoleSetRotateKeyHelpSyn = `Rotate the service account key used to generate access tokens for a roleset.`
const pathRoleSetRotateKeyHelpDesc = `
This path allows you to rotate (i.e. recreate) the service account key 
used to generate access tokens under a given role set. This path only
applies to role sets that generate access tokens and will not delete
the associated service account.`

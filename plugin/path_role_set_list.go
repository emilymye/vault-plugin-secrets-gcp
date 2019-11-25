package gcpsecrets

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRoleSetList(b *backend) *framework.Path {
	// Paths for listing role sets
	return &framework.Path{
		Pattern: "rolesets?/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRoleSetList,
			},
		},
		HelpSynopsis:    pathListRoleSetHelpSyn,
		HelpDescription: pathListRoleSetHelpDesc,
	}
}

func (b *backend) pathRoleSetList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rolesets, err := req.Storage.List(ctx, "roleset/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(rolesets), nil
}

const pathListRoleSetHelpSyn = `List existing rolesets.`
const pathListRoleSetHelpDesc = `List created role sets.`

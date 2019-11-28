package gcpsecrets

import (
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
	"github.com/hashicorp/vault/sdk/framework"
)

type inputParams struct {
	name       string
	secretType string

	hasBindings bool
	rawBindings string
	bindings    ResourceBindings

	project             string
	serviceAccountEmail string

	scopes []string
}

func (input *inputParams) parseOkInputSecretType(d *framework.FieldData) (warnings []string, err error) {
	v, ok := d.GetOk("secret_type")
	if !ok && input.secretType == "" {
		return nil, fmt.Errorf("secret_type required on create")
	}

	secretType := v.(string)
	if input.secretType != "" && input.secretType != secretType {
		return nil, fmt.Errorf("cannot update secret_type")
	}

	switch secretType {
	case SecretTypeKey, SecretTypeAccessToken:
		input.secretType = secretType
		return nil, nil
	default:
		return nil, fmt.Errorf(`invalid "secret_type" value: %q"`, v)
	}
}

func (input *inputParams) parseOkInputEmail(d *framework.FieldData) (warnings []string, err error) {
	v, ok := d.GetOk("email")
	if !ok && input.serviceAccountEmail == "" {
		return nil, fmt.Errorf("email is required on create")
	}

	email := v.(string)
	if input.serviceAccountEmail != "" && input.serviceAccountEmail != email {
		return nil, fmt.Errorf("cannot update secret_type")
	}
	input.serviceAccountEmail = email
	return nil, nil
}

func (input *inputParams) parseOkInputTokenScopes(d *framework.FieldData) (warnings []string, err error) {
	if input.secretType == "" {
		warnings, err = input.parseOkInputTokenScopes(d)
		if err != nil {
			return nil, err
		}
	}

	v, ok := d.GetOk("token_scopes")
	if !ok {
		return nil, nil
	}
	scopes, castOk := v.([]string)
	if !castOk {
		return nil, fmt.Errorf("scopes unexpected type %T, expected []string", v)
	}

	if input.secretType == SecretTypeAccessToken && (!ok || len(scopes) > 0) {
		return nil, fmt.Errorf("non-empty token_scopes must be provided for generating access token secrets")
	}

	if input.secretType != SecretTypeAccessToken && ok && len(scopes) > 0 {
		warnings = append(warnings, "ignoring non-empty token scopes, secret type not access_token")
		return
	}

	input.scopes = scopes
	return
}

func (input *inputParams) parseOkInputBindings(d *framework.FieldData) (warnings []string, err error) {
	bRaw, ok := d.GetOk("bindings")
	if !ok {
		input.hasBindings = false
		return nil, nil
	}

	rawBindings, castok := bRaw.(string)
	if !castok {
		return nil, fmt.Errorf("bindings are not a string")
	}

	bindings, err := util.ParseBindings(bRaw.(string))
	if err != nil {
		return nil, errwrap.Wrapf("unable to parse bindings: {{err}}", err)
	}

	input.hasBindings = true
	input.rawBindings = rawBindings
	input.bindings = bindings
	return nil, nil
}

// This is completely ripped off of https://github.com/hashicorp/terraform-provider-tls
// Modified to sign SSH public keys and generate authorized_key entry

package sshca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"golang.org/x/crypto/ssh"
)

type keyParser func([]byte) (interface{}, error)

var keyParsers map[string]keyParser = map[string]keyParser{
	"RSA": func(der []byte) (interface{}, error) {
		return x509.ParsePKCS1PrivateKey(der)
	},
	"ECDSA": func(der []byte) (interface{}, error) {
		return x509.ParseECPrivateKey(der)
	},
}

func decodePEM(d *schema.ResourceData, pemKey, pemType string) (*pem.Block, error) {
	block, _ := pem.Decode([]byte(d.Get(pemKey).(string)))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", pemKey)
	}
	if pemType != "" && block.Type != pemType {
		return nil, fmt.Errorf("invalid PEM type in %s: %s", pemKey, block.Type)
	}

	return block, nil
}

func parsePrivateKey(d *schema.ResourceData, pemKey, algoKey string) (interface{}, error) {
	algoName := d.Get(algoKey).(string)

	keyFunc, ok := keyParsers[algoName]
	if !ok {
		return nil, fmt.Errorf("invalid %s: %#v", algoKey, algoName)
	}

	block, err := decodePEM(d, pemKey, "")
	if err != nil {
		return nil, err
	}

	key, err := keyFunc(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %s: %s", pemKey, err)
	}

	return key, nil
}

func parseAuthorizedKey(d *schema.ResourceData, authorizedKey string) (ssh.PublicKey, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(d.Get(authorizedKey).(string)))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key error: %s", err)
	}

	return publicKey, nil
}

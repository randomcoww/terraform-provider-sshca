// This is completely ripped off of https://github.com/hashicorp/terraform-provider-tls
// Modified to sign SSH public keys and generate authorized_key entry

package sshca

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"golang.org/x/crypto/ssh"
)

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"ssh_host_cert":   resourceHostCert(),
			"ssh_client_cert": resourceClientCert(),
		},
	}
}

func hashForState(value string) string {
	if value == "" {
		return ""
	}
	hash := sha1.Sum([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(hash[:])
}

var permissionsSchema *schema.Resource = &schema.Resource{
	Schema: map[string]*schema.Schema{
		"critical_options": {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			ForceNew: true,
		},
		"extensions": {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			ForceNew: true,
		},
	},
}

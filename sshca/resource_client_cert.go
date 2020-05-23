package sshca

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"golang.org/x/crypto/ssh"
)

func resourceClientCert() *schema.Resource {
	return &schema.Resource{
		Create:        CreateClientCert,
		Delete:        DeleteCertificate,
		Read:          ReadCertificate,
		Update:        UpdateCertificate,
		CustomizeDiff: CustomizeCertificateDiff,
		Schema:        resourceCertificateCommonSchema(),
	}
}

func CreateClientCert(d *schema.ResourceData, meta interface{}) error {
	cert := &ssh.Certificate{
		CertType: certTypeClient,
	}

	return CreateCertificate(d, cert, meta)
}

package ssh

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"golang.org/x/crypto/ssh"
)

func resourceHostCert() *schema.Resource {
	return &schema.Resource{
		Create:        CreateHostCert,
		Delete:        DeleteCertificate,
		Read:          ReadCertificate,
		Update:        UpdateCertificate,
		CustomizeDiff: CustomizeCertificateDiff,
		Schema:        resourceCertificateCommonSchema(),
	}
}

func CreateHostCert(d *schema.ResourceData, meta interface{}) error {
	cert := &ssh.Certificate{
		CertType: certTypeHost,
	}

	return CreateCertificate(d, cert, meta)
}

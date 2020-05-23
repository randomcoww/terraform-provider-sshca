package sshca

import (
	"fmt"
	"testing"

	r "github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"golang.org/x/crypto/ssh"
)

func TestClientCert(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
                    resource "sshca_client_cert" "test1" {
												key_algorithm = "ECDSA"
                        private_key_pem = <<EOT
%s
EOT
												public_key_openssh = "%s"
												validity_period_hours = 600
												early_renewal_hours = 300
												key_id = "testUser"
												valid_principals = [
													"test1.host.local",
													"test2.host.local",
												]
												extensions = [
													"permit-X11-forwarding",
													"permit-agent-forwarding",
												]
										}

                    output "authorized_key" {
                        value = sshca_client_cert.test1.cert_authorized_key
										}
                `, testPrivateKey, testPublicKeyOpenSSH),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["authorized_key"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"authorized_key\" is not a string")
					}

					publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(got))
					if err != nil {
						return fmt.Errorf("error parsing authorized key: %s", err)
					}
					if expected, got := ssh.CertAlgoECDSA521v01, publicKey.Type(); got != expected {
						return fmt.Errorf("incorrect public key type: expected %v, got %v", expected, got)
					}

					return nil
				},
			},
		},
	})
}

package sshca

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

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
						ca_key_algorithm = "ECDSA"
						ca_private_key_pem = <<EOT
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
						critical_options = [
							"permit-port-forwarding",
							"permit-pty",
						]
					}

					output "authorized_key" {
						value = sshca_client_cert.test1.cert_authorized_key
					}`, testPrivateKey, testPublicKeyOpenSSH),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["authorized_key"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"authorized_key\" is not a string")
					}

					key, _ := base64.StdEncoding.DecodeString(strings.Split(got, " ")[1])
					parsedKey, err := ssh.ParsePublicKey(key)
					if err != nil {
						return fmt.Errorf("error parsing authorized key: %s", err)
					}
					cert := parsedKey.(*ssh.Certificate)

					if expected, got := "testUser", cert.KeyId; got != expected {
						return fmt.Errorf("incorrect KeyId: %v, wanted %v", got, expected)
					}

					if expected, got := uint32(1), cert.CertType; got != expected {
						return fmt.Errorf("incorrect CertType: %v, wanted %v", got, expected)
					}

					if cert.Signature == nil {
						return fmt.Errorf("incorrect Signature: %v", cert.Signature)
					}

					if time.Unix(int64(cert.ValidAfter), 0).After(time.Now()) {
						return fmt.Errorf("incorrect ValidAfter: %v", cert.ValidAfter)
					}

					if time.Unix(int64(cert.ValidBefore), 0).Before(time.Now()) {
						return fmt.Errorf("incorrect ValidBefore: %v", cert.ValidBefore)
					}

					if expected, got := 600*time.Hour, time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0)); got != expected {
						return fmt.Errorf("incorrect ttl: expected: %v, actualL %v", expected, got)
					}

					principals := []string{
						"test1.host.local",
						"test2.host.local",
					}
					if expected, got := principals, cert.ValidPrincipals; !reflect.DeepEqual(got, expected) {
						return fmt.Errorf("incorrect ValidPrincipals: expected: %#v actual: %#v", expected, got)
					}

					permissions := map[string]string{
						"permit-X11-forwarding":   "",
						"permit-agent-forwarding": "",
					}
					if expected, got := permissions, cert.Permissions.Extensions; !reflect.DeepEqual(got, expected) {
						return fmt.Errorf("incorrect Permissions.Extensions: expected: %#v actual: %#v", expected, got)
					}

					criticalOptions := map[string]string{
						"permit-port-forwarding": "",
						"permit-pty":             "",
					}
					if expected, got := criticalOptions, cert.Permissions.CriticalOptions; !reflect.DeepEqual(got, expected) {
						return fmt.Errorf("incorrect Permissions.CriticalOptions: expected: %#v actual: %#v", expected, got)
					}

					return nil
				},
			},
		},
	})
}

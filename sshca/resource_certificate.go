package sshca

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"golang.org/x/crypto/ssh"
)

const (
	certTypeClient = 1
	certTypeHost   = 2
)

var now = func() time.Time {
	return time.Now()
}

func resourceCertificateCommonSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"key_algorithm": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the algorithm to use to generate the certificate's private key",
			ForceNew:    true,
		},

		"private_key_pem": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "PEM-encoded private key that the certificate will belong to",
			ForceNew:    true,
			Sensitive:   true,
			StateFunc: func(v interface{}) string {
				return hashForState(v.(string))
			},
		},

		"public_key_openssh": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Authorized keys formatted SSH public key to sign",
			ForceNew:    true,
		},

		"validity_period_hours": {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "Number of hours that the certificate will remain valid for",
			ForceNew:    true,
		},

		"early_renewal_hours": {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     0,
			Description: "Number of hours before the certificates expiry when a new certificate will be generated",
		},

		"key_id": {
			Type:        schema.TypeString,
			Optional:    true,
			ForceNew:    true,
			Description: "User or host identifier for certificate",
		},

		"valid_principals": {
			Type:        schema.TypeList,
			Required:    true,
			Description: "List of hostnames to use as subjects of the certificate",
			ForceNew:    true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},

		"critical_options": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "Certficate usage permissions - list of critical options",
			ForceNew:    true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},

		"extensions": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "Certficate usage permissions - list of extensions",
			ForceNew:    true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},

		"cert_authorized_key": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"ready_for_renewal": {
			Type:     schema.TypeBool,
			Computed: true,
		},

		"validity_start_time": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"validity_end_time": {
			Type:     schema.TypeString,
			Computed: true,
		},
	}
}

func CreateCertificate(d *schema.ResourceData, cert *ssh.Certificate, meta interface{}) error {
	publicKey, err := parseAuthorizedKey(d, "public_key_openssh")
	if err != nil {
		return err
	}
	cert.Key = publicKey

	permissions := ssh.Permissions{
		CriticalOptions: make(map[string]string),
		Extensions:      make(map[string]string),
	}
	criticalOptionsI := d.Get("critical_options").([]interface{})
	for _, criticalOptionI := range criticalOptionsI {
		permissions.CriticalOptions[criticalOptionI.(string)] = ""
	}
	extensionsI := d.Get("extensions").([]interface{})
	for _, extensionI := range extensionsI {
		permissions.Extensions[extensionI.(string)] = ""
	}
	cert.Permissions = permissions

	validPrincipalsI := d.Get("valid_principals").([]interface{})
	for _, principalI := range validPrincipalsI {
		cert.ValidPrincipals = append(cert.ValidPrincipals, principalI.(string))
	}

	timeNow := now()
	timeExpire := timeNow.Add(time.Duration(d.Get("validity_period_hours").(int)) * time.Hour)
	cert.ValidBefore = uint64(timeNow.Unix())
	cert.ValidAfter = uint64(timeExpire.Unix())

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	cert.Serial = serial.Uint64()
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %s", err)
	}

	privateKey, err := parsePrivateKey(d, "private_key_pem", "key_algorithm")
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return err
	}
	cert.SignCert(rand.Reader, signer)
	certAuthorizedKey := ssh.MarshalAuthorizedKey(cert)

	validFromBytes, err := time.Unix(int64(cert.ValidAfter), 0).MarshalText()
	if err != nil {
		return fmt.Errorf("error serializing validity_start_time: %s", err)
	}
	validToBytes, err := time.Unix(int64(cert.ValidBefore), 0).MarshalText()
	if err != nil {
		return fmt.Errorf("error serializing validity_end_time: %s", err)
	}

	d.SetId(fmt.Sprint(cert.Serial))
	d.Set("cert_authorized_key", fmt.Sprintf("%s", certAuthorizedKey))
	d.Set("ready_for_renewal", false)
	d.Set("validity_start_time", string(validFromBytes))
	d.Set("validity_end_time", string(validToBytes))

	return nil
}

func DeleteCertificate(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func ReadCertificate(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func CustomizeCertificateDiff(d *schema.ResourceDiff, meta interface{}) error {
	var readyForRenewal bool

	endTimeStr := d.Get("validity_end_time").(string)
	endTime := now()
	err := endTime.UnmarshalText([]byte(endTimeStr))
	if err != nil {
		// If end time is invalid then we'll treat it as being at the time for renewal.
		readyForRenewal = true
	} else {
		earlyRenewalPeriod := time.Duration(-d.Get("early_renewal_hours").(int)) * time.Hour
		endTime = endTime.Add(earlyRenewalPeriod)

		currentTime := now()
		timeToRenewal := endTime.Sub(currentTime)
		if timeToRenewal <= 0 {
			readyForRenewal = true
		}
	}

	if readyForRenewal {
		err = d.SetNew("ready_for_renewal", true)
		if err != nil {
			return err
		}
		err = d.ForceNew("ready_for_renewal")
		if err != nil {
			return err
		}
	}

	return nil
}

func UpdateCertificate(d *schema.ResourceData, meta interface{}) error {
	return nil
}

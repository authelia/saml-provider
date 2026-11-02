package saml

import (
	"encoding/base64"
	"os"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestIDPEncryptionFailsClosed(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	certData := base64.StdEncoding.EncodeToString(test.SPCertificate.Raw)
	withCert := func(use string) KeyDescriptor {
		return KeyDescriptor{Use: use, KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: certData}}}}}
	}
	role := func(keys ...KeyDescriptor) SPSSODescriptor {
		return SPSSODescriptor{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{KeyDescriptors: keys}}}
	}

	for _, tc := range []struct {
		name     string
		selected SPSSODescriptor
		others   []SPSSODescriptor
		want     string
	}{
		{name: "unspecified use with no certificate", selected: role(KeyDescriptor{}), want: "fail"},
		{name: "unspecified use with no certificate and signing", selected: role(KeyDescriptor{}, withCert("signing")), want: "fail"},
		{name: "unrecognised use, wrong case", selected: role(withCert("Encryption")), want: "fail"},
		{name: "unrecognised use, whitespace", selected: role(withCert(" encryption")), want: "fail"},
		{name: "unrecognised use, both", selected: role(withCert("both")), want: "fail"},
		{name: "unrecognised use alongside a usable key", selected: role(withCert("both"), withCert("encryption")), want: "encrypted"},
		{name: "another descriptor has an encryption key", selected: role(withCert("signing")), others: []SPSSODescriptor{role(withCert("encryption"))}, want: "fail"},
		{name: "another descriptor has an unspecified key", selected: role(), others: []SPSSODescriptor{role(withCert(""))}, want: "fail"},
		{name: "another descriptor has only signing keys", selected: role(withCert("signing")), others: []SPSSODescriptor{role(withCert("signing"))}, want: "plaintext"},
		{name: "no keys at all", selected: role(), want: "plaintext"},
		{name: "selected descriptor has its own key", selected: role(withCert("encryption")), others: []SPSSODescriptor{role()}, want: "encrypted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := tc.selected
			req := &IdpAuthnRequest{
				SPSSODescriptor:         &selected,
				ServiceProviderMetadata: &EntityDescriptor{SPSSODescriptors: append([]SPSSODescriptor{selected}, tc.others...)},
			}
			cert, err := req.getSPEncryptionCert()
			switch tc.want {
			case "encrypted":
				assert.Check(t, err)
				assert.Check(t, cert != nil)
			case "plaintext":
				assert.Check(t, is.Equal(os.ErrNotExist, err))
			default:
				assert.Check(t, err != nil && err != os.ErrNotExist, "err=%v", err)
			}
		})
	}
}

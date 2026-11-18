package saml

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // The digest of a key hint, which identifies a certificate and protects nothing.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// encryptionTestKeys are RSA-2048 keys which the tests of the encryption keys share, as they are slow to make.
var encryptionTestKeys = sync.OnceValue(func() []*rsa.PrivateKey {
	keys := make([]*rsa.PrivateKey, 3)

	for i := range keys {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		keys[i] = key
	}

	return keys
})

// encryptionTestCertificate returns a self-signed certificate for the public key, as edit changes it.
func encryptionTestCertificate(t *testing.T, key crypto.Signer, commonName string, edit func(*x509.Certificate)) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if edit != nil {
		edit(template)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	return cert
}

// encryptionTestPair returns the i-th shared key as a key pair of the identity provider.
func encryptionTestPair(t *testing.T, i int, commonName string) DecryptionKey {
	t.Helper()

	key := encryptionTestKeys()[i]

	return DecryptionKey{Certificate: encryptionTestCertificate(t, key, commonName, nil), Key: key}
}

// countingDecrypter is a key which is not an *rsa.PrivateKey, as one in a hardware security module is not, and
// which counts the private key operations that it is asked for.
type countingDecrypter struct {
	key   *rsa.PrivateKey
	calls int
}

func (d *countingDecrypter) Public() crypto.PublicKey { return d.key.Public() }

func (d *countingDecrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	d.calls++

	return d.key.Decrypt(rand, msg, opts)
}

// encrypterToCertificate returns the encrypter of the service provider to the identity provider, to cert in place
// of the key of its metadata.
func encrypterToCertificate(t *testing.T, test *IdentityProviderTest, cert *x509.Certificate) *elementEncrypter {
	t.Helper()

	encrypter := *idpEncrypter(t, test)
	encrypter.certificate = cert

	return &encrypter
}

// encryptionKeyDescriptors returns the certificates of the encryption KeyDescriptors.
func encryptionKeyDescriptors(descriptors []KeyDescriptor) []KeyDescriptor {
	var rv []KeyDescriptor

	for _, descriptor := range descriptors {
		if descriptor.Use == "encryption" {
			rv = append(rv, descriptor)
		}
	}

	return rv
}

// metadataString returns the metadata of the identity provider as it is served.
func metadataString(t *testing.T, idp *IdentityProvider) string {
	t.Helper()

	buf, err := xml.Marshal(idp.Metadata())
	assert.NilError(t, err)

	return string(buf)
}

func TestIDPMetadataPublishesSeparateEncryptionKey(t *testing.T) {
	current := encryptionTestPair(t, 0, "idp encryption")

	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, current.Key

	assert.NilError(t, test.IDP.CheckEncryptionKeys())

	descriptors := test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors
	assert.Assert(t, is.DeepEqual([]string{"signing", "encryption"}, keyDescriptorUses(descriptors)))

	// The signing key is only for signing, and the encryption key is the only key to encrypt to.
	assert.Check(t, is.Equal(encodeCertificate(test.Certificate), descriptors[0].KeyInfo.X509Data.X509Certificates[0].Data))
	assert.Check(t, is.Len(descriptors[0].EncryptionMethods, 0))
	assert.Assert(t, is.Len(descriptors[1].KeyInfo.X509Data.X509Certificates, 1))
	assert.Check(t, is.Equal(encodeCertificate(current.Certificate), descriptors[1].KeyInfo.X509Data.X509Certificates[0].Data))
	assert.Check(t, is.DeepEqual(test.IDP.encryptionMethods(), descriptors[1].EncryptionMethods))
	assert.Check(t, len(descriptors[1].EncryptionMethods) != 0)
}

// Without an encryption key of its own, the identity provider is encrypted to with its RSA signing key, as before.
func TestIDPMetadataEncryptionKeyFallsBackToSigningKey(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	assert.NilError(t, test.IDP.CheckEncryptionKeys())

	descriptors := test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors
	assert.Assert(t, is.DeepEqual([]string{"signing", "encryption"}, keyDescriptorUses(descriptors)))
	assert.Check(t, is.Equal(encodeCertificate(test.Certificate), descriptors[1].KeyInfo.X509Data.X509Certificates[0].Data))
}

// A signing certificate which states what its key is for, and not that it is for encrypting keys, is not
// advertised for encryption.
func TestIDPMetadataFallbackRespectsKeyUsage(t *testing.T) {
	key := encryptionTestKeys()[0]

	for name, tc := range map[string]struct {
		usage    x509.KeyUsage
		expected []string
	}{
		"signature only":   {x509.KeyUsageDigitalSignature, []string{"signing"}},
		"key encipherment": {x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, []string{"signing", "encryption"}},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			test.IDP.Key = key
			test.IDP.Certificate = encryptionTestCertificate(t, key, "idp", func(c *x509.Certificate) { c.KeyUsage = tc.usage })

			assert.Check(t, is.DeepEqual(tc.expected, keyDescriptorUses(test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors)))
		})
	}
}

// An identity provider which can't decrypt with its signing key, because it is an ECDSA key or only a Signer,
// can still be encrypted to with an encryption key of its own.
func TestIDPMetadataEncryptionKeyWithSigningKeyThatCannotDecrypt(t *testing.T) {
	current := encryptionTestPair(t, 0, "idp encryption")

	for name, configure := range map[string]func(t *testing.T, test *IdentityProviderTest){
		"ecdsa signing key": func(t *testing.T, test *IdentityProviderTest) {
			test.IDP.Key, test.IDP.Certificate = newECDSATestKey(t, elliptic.P256())
		},
		"signer": func(_ *testing.T, test *IdentityProviderTest) {
			test.IDP.Signer, test.IDP.Key = opaqueSigner{test.Key.(crypto.Signer)}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			configure(t, test)

			assert.Check(t, is.DeepEqual([]string{"signing"}, keyDescriptorUses(test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors)))

			test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, &countingDecrypter{key: encryptionTestKeys()[0]}

			descriptors := test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors
			assert.Assert(t, is.DeepEqual([]string{"signing", "encryption"}, keyDescriptorUses(descriptors)))
			assert.Check(t, is.Equal(encodeCertificate(test.IDP.Certificate), descriptors[0].KeyInfo.X509Data.X509Certificates[0].Data))
			assert.Check(t, is.Equal(encodeCertificate(current.Certificate), descriptors[1].KeyInfo.X509Data.X509Certificates[0].Data))
		})
	}
}

// The keys that are only decrypted with are not in the metadata at all, whichever key is published.
func TestIDPMetadataDoesNotPublishDecryptionKeys(t *testing.T) {
	current := encryptionTestPair(t, 0, "idp encryption")
	previous := encryptionTestPair(t, 1, "idp encryption")

	for name, separate := range map[string]bool{"separate key": true, "fallback": false} {
		t.Run(name, func(t *testing.T) {
			f := newQueryFixture(t)
			idp := &f.test.IDP
			idp.DecryptionKeys = []DecryptionKey{previous}

			expected := f.test.Certificate
			if separate {
				idp.EncryptionCertificate, idp.EncryptionKey = current.Certificate, current.Key
				expected = current.Certificate
			}

			assert.NilError(t, idp.CheckEncryptionKeys())

			metadata := idp.Metadata()

			encryption := encryptionKeyDescriptors(metadata.IDPSSODescriptors[0].KeyDescriptors)
			assert.Assert(t, is.Len(encryption, 1))
			assert.Check(t, is.Equal(encodeCertificate(expected), encryption[0].KeyInfo.X509Data.X509Certificates[0].Data))
			assert.Check(t, !strings.Contains(metadataString(t, idp), encodeCertificate(previous.Certificate)))

			// Nothing is encrypted to the authorities that answer queries.
			assert.Check(t, is.Len(encryptionKeyDescriptors(metadata.AttributeAuthorityDescriptors[0].KeyDescriptors), 0))
			assert.Check(t, is.Len(encryptionKeyDescriptors(metadata.AuthnAuthorityDescriptors[0].KeyDescriptors), 0))
		})
	}
}

func TestIDPCheckEncryptionKeys(t *testing.T) {
	keys := encryptionTestKeys()
	current := encryptionTestPair(t, 0, "current")
	previous := encryptionTestPair(t, 1, "previous")
	_, ecdsaCertificate := newECDSATestKey(t, elliptic.P256())

	usage := func(usage x509.KeyUsage) *x509.Certificate {
		return encryptionTestCertificate(t, keys[0], "current", func(c *x509.Certificate) { c.KeyUsage = usage })
	}
	expired := encryptionTestCertificate(t, keys[0], "current", func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	})

	var nilKey *rsa.PrivateKey

	for name, tc := range map[string]struct {
		configure func(test *IdentityProviderTest)
		err       string
	}{
		"nothing configured": {configure: func(*IdentityProviderTest) {}},
		"separate key": {configure: func(test *IdentityProviderTest) {
			test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, current.Key
		}},
		"opaque key": {configure: func(test *IdentityProviderTest) {
			test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, &countingDecrypter{key: keys[0]}
		}},
		"key encipherment usage": {configure: func(test *IdentityProviderTest) {
			test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = usage(x509.KeyUsageKeyEncipherment), current.Key
		}},
		"expired certificate": {configure: func(test *IdentityProviderTest) {
			test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = expired, current.Key
		}},
		"decryption keys which repeat": {configure: func(test *IdentityProviderTest) {
			test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, current.Key
			test.IDP.DecryptionKeys = []DecryptionKey{current, previous, previous, current}
		}},
		"certificate without key": {
			configure: func(test *IdentityProviderTest) { test.IDP.EncryptionCertificate = current.Certificate },
			err:       "IdentityProvider.EncryptionCertificate and EncryptionKey must be set together",
		},
		"key without certificate": {
			configure: func(test *IdentityProviderTest) { test.IDP.EncryptionKey = current.Key },
			err:       "IdentityProvider.EncryptionCertificate and EncryptionKey must be set together",
		},
		"nil key in the interface": {
			configure: func(test *IdentityProviderTest) {
				test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, nilKey
			},
			err: "IdentityProvider.EncryptionCertificate and EncryptionKey must be set together",
		},
		"certificate with an ecdsa key": {
			configure: func(test *IdentityProviderTest) {
				test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = ecdsaCertificate, current.Key
			},
			err: "IdentityProvider.EncryptionCertificate: the certificate does not have an RSA key",
		},
		"short key": {
			configure: func(test *IdentityProviderTest) {
				test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = test.Certificate, test.Key.(*rsa.PrivateKey)
			},
			err: "IdentityProvider.EncryptionCertificate: the RSA key has 1024 bits, which is fewer than 2048",
		},
		"key of another certificate": {
			configure: func(test *IdentityProviderTest) {
				test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, previous.Key
			},
			err: "IdentityProvider.EncryptionKey: the private key is not that of the certificate",
		},
		"usage without key encipherment": {
			configure: func(test *IdentityProviderTest) {
				test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = usage(x509.KeyUsageDigitalSignature), current.Key
			},
			err: "IdentityProvider.EncryptionCertificate: the key usage of the certificate does not include key encipherment",
		},
		"decryption key without certificate": {
			configure: func(test *IdentityProviderTest) {
				test.IDP.DecryptionKeys = []DecryptionKey{previous, {Key: current.Key}}
			},
			err: "IdentityProvider.DecryptionKeys[1]: the certificate and the key must both be set",
		},
		"decryption key without key": {
			configure: func(test *IdentityProviderTest) {
				test.IDP.DecryptionKeys = []DecryptionKey{{Certificate: previous.Certificate}}
			},
			err: "IdentityProvider.DecryptionKeys[0]: the certificate and the key must both be set",
		},
		"decryption key of another certificate": {
			configure: func(test *IdentityProviderTest) {
				test.IDP.DecryptionKeys = []DecryptionKey{{Certificate: previous.Certificate, Key: current.Key}}
			},
			err: "IdentityProvider.DecryptionKeys[0]: the private key is not that of the certificate",
		},
		"short decryption key": {
			configure: func(test *IdentityProviderTest) {
				test.IDP.DecryptionKeys = []DecryptionKey{{Certificate: test.Certificate, Key: test.Key.(*rsa.PrivateKey)}}
			},
			err: "IdentityProvider.DecryptionKeys[0]: the RSA key has 1024 bits, which is fewer than 2048",
		},
		"too many decryption keys": {
			configure: func(test *IdentityProviderTest) {
				for _, name := range []string{"a", "b", "c", "d", "e"} {
					test.IDP.DecryptionKeys = append(test.IDP.DecryptionKeys, encryptionTestPair(t, 1, name))
				}
			},
			err: "IdentityProvider.DecryptionKeys: more than 4 keys",
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			tc.configure(test)

			err := test.IDP.CheckEncryptionKeys()

			w := httptest.NewRecorder()
			test.IDP.ServeMetadata(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/metadata", nil))

			if tc.err == "" {
				assert.NilError(t, err)
				assert.Check(t, is.Equal(http.StatusOK, w.Code))

				return
			}

			assert.Check(t, is.Error(err, tc.err))

			// Keys that are not valid are neither published nor decrypted with, and no other key takes their place.
			assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
			assert.Check(t, is.DeepEqual([]string{"signing"}, keyDescriptorUses(test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors)))

			_, err = test.IDP.elementDecrypter()
			assert.Check(t, is.Error(err, tc.err))
		})
	}
}

// encryptionKeyConfigurations are the ways an identity provider can hold the key that a message was encrypted to.
// Each configures the identity provider and returns the certificate of that key.
var encryptionKeyConfigurations = map[string]func(t *testing.T, test *IdentityProviderTest) *x509.Certificate{
	"current key": func(t *testing.T, test *IdentityProviderTest) *x509.Certificate {
		current, previous := encryptionTestPair(t, 0, "idp"), encryptionTestPair(t, 1, "idp")
		test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, current.Key
		test.IDP.DecryptionKeys = []DecryptionKey{previous}

		return current.Certificate
	},
	"decryption key": func(t *testing.T, test *IdentityProviderTest) *x509.Certificate {
		current, previous := encryptionTestPair(t, 0, "idp"), encryptionTestPair(t, 1, "idp")
		test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, current.Key
		test.IDP.DecryptionKeys = []DecryptionKey{encryptionTestPair(t, 2, "idp"), previous}

		return previous.Certificate
	},
	"decryption key beside the signing key": func(t *testing.T, test *IdentityProviderTest) *x509.Certificate {
		previous := encryptionTestPair(t, 1, "idp")
		test.IDP.DecryptionKeys = []DecryptionKey{previous}

		return previous.Certificate
	},
	"signing key beside a decryption key": func(t *testing.T, test *IdentityProviderTest) *x509.Certificate {
		test.IDP.DecryptionKeys = []DecryptionKey{encryptionTestPair(t, 1, "idp")}

		return test.Certificate
	},
	"retired signing key": func(t *testing.T, test *IdentityProviderTest) *x509.Certificate {
		current := encryptionTestPair(t, 0, "idp")
		key := encryptionTestKeys()[2]
		retired := encryptionTestCertificate(t, key, "idp signing", nil)

		test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, current.Key
		test.IDP.DecryptionKeys = []DecryptionKey{{Certificate: retired, Key: key}}

		return retired
	},
	"opaque decryption key": func(t *testing.T, test *IdentityProviderTest) *x509.Certificate {
		current, previous := encryptionTestPair(t, 0, "idp"), encryptionTestPair(t, 1, "idp")
		test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = current.Certificate, &countingDecrypter{key: encryptionTestKeys()[0]}
		test.IDP.DecryptionKeys = []DecryptionKey{{Certificate: previous.Certificate, Key: &countingDecrypter{key: encryptionTestKeys()[1]}}}

		return previous.Certificate
	},
}

func TestServeLogoutRequestWithEncryptedIDToEachKey(t *testing.T) {
	for name, configure := range encryptionKeyConfigurations {
		for binding, send := range encryptedLogoutBindings {
			t.Run(name+"/"+binding, func(t *testing.T) {
				test, provider := encryptedLogoutIDP(t)
				cert := configure(t, test)

				status := send(t, test, func(request *LogoutRequest) {
					encryptedID, err := encrypterToCertificate(t, test, cert).encryptNameID(&NameID{
						Format:          string(TransientNameIDFormat),
						NameQualifier:   test.IDP.entityID(),
						SPNameQualifier: test.SP.MetadataURL.String(),
						Value:           "alice",
					})
					assert.NilError(t, err)

					request.NameID, request.EncryptedID = nil, encryptedID
				})
				assert.Check(t, is.Equal(StatusSuccess, status.StatusCode.Value))

				assert.Assert(t, is.Len(provider.lookups, 1))
				assert.Check(t, provider.lookups[0].NameIDEncrypted)
				assert.Check(t, !provider.lookups[0].Unidentified)
				assert.Check(t, is.Equal("alice", provider.lookups[0].Request.NameID.Value))
				assert.Check(t, is.Len(provider.terminated, 1))
			})
		}
	}
}

func TestManageNameIDEncryptedToEachKey(t *testing.T) {
	for name, configure := range encryptionKeyConfigurations {
		for binding, send := range manageNameIDBindings {
			t.Run(name+"/"+binding, func(t *testing.T) {
				test, provider := manageNameIDTestIDP(t)
				cert := configure(t, test)

				result := send(t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
					encrypter := encrypterToCertificate(t, test, cert)

					var err error

					request.EncryptedID, err = encrypter.encryptNameID(request.NameID)
					assert.NilError(t, err)
					request.NewEncryptedID, err = encrypter.encryptNewID("sp-secret-alias")
					assert.NilError(t, err)
				}})
				assert.Assert(t, result.Response != nil, "HTTP status %d", result.Code)
				checkStatus(t, result.Response.Status, StatusSuccess, "")

				assert.Assert(t, is.Len(provider.calls, 1))
				assert.Check(t, is.Equal(provider.calls[0].SPProvidedID, "sp-secret-alias"))
				assert.Check(t, is.DeepEqual(provider.calls[0].NameID, *testNameID(test, &test.SP)))
				assert.Check(t, provider.calls[0].Request.NameIDEncrypted)
				assert.Check(t, provider.calls[0].Request.NewIDEncrypted)
				assert.Check(t, !provider.calls[0].Request.Unidentified)
			})
		}
	}
}

func TestNameIDMappingWithEncryptedIDToEachKey(t *testing.T) {
	for name, configure := range encryptionKeyConfigurations {
		t.Run(name, func(t *testing.T) {
			f := newNameIDMappingFixture(t)
			cert := configure(t, f.test)

			result := f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
				var err error

				request.EncryptedID, err = encrypterToCertificate(t, f.test, cert).encryptNameID(request.NameID)
				assert.NilError(t, err)
			}})
			checkStatus(t, result.Response.Status, StatusSuccess, "")

			assert.Assert(t, is.Len(f.provider.calls, 1))
			assert.Check(t, f.provider.calls[0].NameIDEncrypted)
			assert.Check(t, is.DeepEqual(*f.provider.calls[0].Request.NameID, *testNameID(f.test, f.a)))
		})
	}
}

// ManagedPersistentNameIDProvider is given the identifier that a key which is no longer published decrypted, as
// any other NameIDProvider is, for both of the requests that it serves.
func TestManagedPersistentNameIDProviderWithDecryptionKey(t *testing.T) {
	allow := true

	t.Run("mapping", func(t *testing.T) {
		f, provider, issued := managedMappingFixture(t)
		cert := encryptionKeyConfigurations["decryption key"](t, f.test)
		target := f.b.MetadataURL.String()

		result := f.send(t, nameIDMappingOptions{mutate: func(request *NameIDMappingRequest) {
			var err error

			request.NameID = issued
			request.NameIDPolicy = &NameIDPolicy{SPNameQualifier: &target, AllowCreate: &allow}
			request.EncryptedID, err = encrypterToCertificate(t, f.test, cert).encryptNameID(issued)
			assert.NilError(t, err)
		}})
		checkStatus(t, result.Response.Status, StatusSuccess, "")

		mapped, err := f.b.DecryptNameID(reparse(t, result.Element.FindElement("./EncryptedID")))
		assert.NilError(t, err)

		want, err := provider.NameID(nil, persistentRequest(target, false), &Session{UserName: "alice"})
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(mapped, want))
	})

	for binding, send := range manageNameIDBindings {
		t.Run("management/"+binding, func(t *testing.T) {
			test, provider, _, issued := managedManageNameIDTest(t)
			cert := encryptionKeyConfigurations["decryption key"](t, test)

			result := send(t, test, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
				encrypter := encrypterToCertificate(t, test, cert)

				var err error

				request.NameID = issued
				request.EncryptedID, err = encrypter.encryptNameID(issued)
				assert.NilError(t, err)
				request.NewEncryptedID, err = encrypter.encryptNewID("sp-secret-alias")
				assert.NilError(t, err)
			}})
			assert.Assert(t, result.Response != nil, "HTTP status %d", result.Code)
			checkStatus(t, result.Response.Status, StatusSuccess, "")

			alias, err := provider.SPProvidedID(nil, test.SP.MetadataURL.String(), issued)
			assert.NilError(t, err)
			assert.Check(t, is.Equal(alias, "sp-secret-alias"))
		})
	}
}

// A message encrypted to a key that the identity provider doesn't hold is answered as a NameID which names no
// session is, however many keys were tried (errata E93).
func TestServeLogoutRequestUndecryptableWithSeveralKeys(t *testing.T) {
	for name, hint := range map[string]bool{"with the certificate": true, "without a hint": false} {
		for binding, send := range encryptedLogoutBindings {
			t.Run(name+"/"+binding, func(t *testing.T) {
				unknownTest, unknownProvider := soapLogoutTestIDP(t)
				unknownProvider.sessions = nil
				unknown := send(t, unknownTest, nil)

				test, provider := encryptedLogoutIDP(t)
				encryptionKeyConfigurations["decryption key"](t, test)

				stranger := encryptionTestCertificate(t, encryptionTestKeys()[2], "stranger", nil)
				test.IDP.DecryptionKeys = test.IDP.DecryptionKeys[1:]

				status := send(t, test, func(request *LogoutRequest) {
					encryptedID, err := encrypterToCertificate(t, test, stranger).encryptNameID(&NameID{Value: "alice"})
					assert.NilError(t, err)

					if !hint {
						keyInfo := encryptedID.FindElement("./EncryptedData/KeyInfo/EncryptedKey/KeyInfo")
						keyInfo.Parent().RemoveChild(keyInfo)
					}

					request.NameID, request.EncryptedID = nil, encryptedID
				})
				assert.Check(t, is.DeepEqual(unknown, status))
				assert.Check(t, statusSaysNothingOfTheRequest(status))
				assert.Check(t, status.StatusDetail == nil)

				assert.Assert(t, is.Len(provider.lookups, 1))
				assert.Check(t, provider.lookups[0].Unidentified)
				assert.Check(t, is.Len(provider.terminated, 0))
			})
		}
	}
}

// countedKeys returns an elementDecrypter with a key for each common name, in order, and the keys, which count
// what they are asked to decrypt.
func countedKeys(t *testing.T, commonNames ...string) (elementDecrypter, []*countingDecrypter, []*x509.Certificate) {
	t.Helper()

	decrypter := elementDecrypter{recipient: encryptedElementRecipient}
	counters := make([]*countingDecrypter, 0, len(commonNames))
	certs := make([]*x509.Certificate, 0, len(commonNames))

	for i, commonName := range commonNames {
		key := encryptionTestKeys()[i]
		counter := &countingDecrypter{key: key}
		cert := encryptionTestCertificate(t, key, commonName, func(c *x509.Certificate) {
			c.SerialNumber = big.NewInt(int64(i) + 1)
			c.SubjectKeyId = []byte("key " + commonName + strconv.Itoa(i))
		})

		decrypter.keys = append(decrypter.keys, decryptionKey{certificate: cert, key: counter})
		counters = append(counters, counter)
		certs = append(certs, cert)
	}

	return decrypter, counters, certs
}

// encryptWithKeyInfo encrypts testEncryptedNameID to cert, with keyInfo in place of the children of the KeyInfo
// of the EncryptedKey, or with no KeyInfo if it is nil.
func encryptWithKeyInfo(t *testing.T, cert *x509.Certificate, keyInfo func(parent *etree.Element)) *etree.Element {
	t.Helper()

	encrypter := testElementEncrypter(t, method(aes128GCM))
	encrypter.certificate = cert

	el, err := encrypter.encryptNameID(&testEncryptedNameID)
	assert.NilError(t, err)

	keyInfoEl := el.FindElement("./EncryptedData/KeyInfo/EncryptedKey/KeyInfo")
	assert.Assert(t, keyInfoEl != nil)

	if keyInfo == nil {
		keyInfoEl.Parent().RemoveChild(keyInfoEl)
	} else {
		for _, child := range keyInfoEl.ChildElements() {
			keyInfoEl.RemoveChild(child)
		}

		keyInfo(keyInfoEl)
	}

	return reparse(t, el)
}

func calls(counters []*countingDecrypter) []int {
	rv := make([]int, len(counters))
	for i, counter := range counters {
		rv[i] = counter.calls
	}

	return rv
}

// The KeyInfo of the EncryptedKey selects the keys that are tried, when it identifies a certificate of the
// identity provider. Otherwise every key is tried.
func TestElementDecrypterSelectsKeyByKeyInfo(t *testing.T) {
	x509Data := func(tag, text string) func(*etree.Element) {
		return func(parent *etree.Element) {
			parent.CreateElement("ds:X509Data").CreateElement("ds:" + tag).SetText(text)
		}
	}

	for name, tc := range map[string]struct {
		commonNames []string
		keyInfo     func(cert *x509.Certificate) func(*etree.Element)
		expected    []int
	}{
		"certificate": {
			keyInfo: func(cert *x509.Certificate) func(*etree.Element) {
				return x509Data("X509Certificate", encodeCertificate(cert))
			},
			expected: []int{0, 1, 0},
		},
		"subject key identifier": {
			keyInfo: func(cert *x509.Certificate) func(*etree.Element) {
				return x509Data("X509SKI", base64.StdEncoding.EncodeToString(cert.SubjectKeyId))
			},
			expected: []int{0, 1, 0},
		},
		"subject name": {
			keyInfo: func(cert *x509.Certificate) func(*etree.Element) {
				return x509Data("X509SubjectName", cert.Subject.String())
			},
			expected: []int{0, 1, 0},
		},
		"sha-256 digest": {
			keyInfo: func(cert *x509.Certificate) func(*etree.Element) {
				return func(parent *etree.Element) {
					digest := sha256.Sum256(cert.Raw)
					el := parent.CreateElement("ds:X509Data").CreateElement("dsig11:X509Digest")
					el.CreateAttr("xmlns:dsig11", "http://www.w3.org/2009/xmldsig11#")
					el.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
					el.SetText(base64.StdEncoding.EncodeToString(digest[:]))
				}
			},
			expected: []int{0, 1, 0},
		},
		"sha-1 digest": {
			keyInfo: func(cert *x509.Certificate) func(*etree.Element) {
				return func(parent *etree.Element) {
					digest := sha1.Sum(cert.Raw) //nolint:gosec // See the import.
					el := parent.CreateElement("ds:X509Data").CreateElement("dsig11:X509Digest")
					el.CreateAttr("xmlns:dsig11", "http://www.w3.org/2009/xmldsig11#")
					el.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
					el.SetText(base64.StdEncoding.EncodeToString(digest[:]))
				}
			},
			expected: []int{0, 1, 0},
		},
		"key name of the common name": {
			keyInfo: func(cert *x509.Certificate) func(*etree.Element) {
				return func(parent *etree.Element) { parent.CreateElement("ds:KeyName").SetText(cert.Subject.CommonName) }
			},
			expected: []int{0, 1, 0},
		},
		"key name of the subject": {
			keyInfo: func(cert *x509.Certificate) func(*etree.Element) {
				return func(parent *etree.Element) { parent.CreateElement("ds:KeyName").SetText(cert.Subject.String()) }
			},
			expected: []int{0, 1, 0},
		},
		"rsa key value": {
			keyInfo: func(cert *x509.Certificate) func(*etree.Element) {
				return func(parent *etree.Element) {
					key := cert.PublicKey.(*rsa.PublicKey)
					el := parent.CreateElement("ds:KeyValue").CreateElement("ds:RSAKeyValue")
					el.CreateElement("ds:Modulus").SetText(base64.StdEncoding.EncodeToString(key.N.Bytes()))
					el.CreateElement("ds:Exponent").SetText(base64.StdEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()))
				}
			},
			expected: []int{0, 1, 0},
		},
		// Certificates of one subject, as is usual across a rollover, are all identified by its name.
		"key name that two certificates share": {
			commonNames: []string{"idp", "idp", "other"},
			keyInfo: func(cert *x509.Certificate) func(*etree.Element) {
				return func(parent *etree.Element) { parent.CreateElement("ds:KeyName").SetText(cert.Subject.CommonName) }
			},
			expected: []int{1, 1, 0},
		},
		"key name of no certificate": {
			keyInfo: func(*x509.Certificate) func(*etree.Element) {
				return func(parent *etree.Element) { parent.CreateElement("ds:KeyName").SetText("somebody else") }
			},
			expected: []int{1, 1, 1},
		},
		"empty key info": {
			keyInfo:  func(*x509.Certificate) func(*etree.Element) { return func(*etree.Element) {} },
			expected: []int{1, 1, 1},
		},
		"no key info": {
			keyInfo:  func(*x509.Certificate) func(*etree.Element) { return nil },
			expected: []int{1, 1, 1},
		},
	} {
		t.Run(name, func(t *testing.T) {
			commonNames := tc.commonNames
			if commonNames == nil {
				commonNames = []string{"first", "second", "third"}
			}

			decrypter, counters, certs := countedKeys(t, commonNames...)

			nameID, err := decrypter.decryptNameID(encryptWithKeyInfo(t, certs[1], tc.keyInfo(certs[1])))
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(testEncryptedNameID, *nameID))
			assert.Check(t, is.DeepEqual(tc.expected, calls(counters)))
		})
	}
}

// The private key operations that a message costs don't depend on which key decrypts it, or on whether one does:
// every key that the KeyInfo doesn't rule out is used once, so that the time taken tells a requester nothing about
// the keys of the identity provider or about the ciphertext (errata E93).
func TestElementDecrypterTriesEveryCandidateKey(t *testing.T) {
	stranger := encryptionTestCertificate(t, encryptionTestKeys()[2], "stranger", nil)

	for name, tc := range map[string]struct {
		recipient int
		err       bool
	}{
		"the first key decrypts": {recipient: 0},
		"the last key decrypts":  {recipient: 1},
		"no key decrypts":        {recipient: -1, err: true},
	} {
		t.Run(name, func(t *testing.T) {
			decrypter, counters, certs := countedKeys(t, "first", "second")

			cert := stranger
			if tc.recipient >= 0 {
				cert = certs[tc.recipient]
			}

			nameID, err := decrypter.decryptNameID(encryptWithKeyInfo(t, cert, nil))
			if tc.err {
				assert.Check(t, is.Error(err, "failed to decrypt key from response: crypto/rsa: decryption error"))
			} else {
				assert.NilError(t, err)
				assert.Check(t, is.DeepEqual(testEncryptedNameID, *nameID))
			}

			assert.Check(t, is.DeepEqual([]int{1, 1}, calls(counters)))
		})
	}

	// A certificate that is none of the identity provider's is refused before any private key is used.
	t.Run("certificate of no key", func(t *testing.T) {
		decrypter, counters, _ := countedKeys(t, "first", "second")

		el, err := testElementEncrypter(t, method(aes128GCM)).encryptNameID(&testEncryptedNameID)
		assert.NilError(t, err)

		_, err = decrypter.decryptNameID(reparse(t, el))
		assert.Check(t, is.Error(err, "failed to decrypt key from response: certificate does not match provided key"))
		assert.Check(t, is.DeepEqual([]int{0, 0}, calls(counters)))
	})
}

// The whole sequence by which the encryption key is changed, with a service provider that refreshes the metadata
// late: at every step, what it encrypts to the key it knows is decrypted.
func TestIDPEncryptionKeyRollover(t *testing.T) {
	old, next := encryptionTestPair(t, 0, "idp"), encryptionTestPair(t, 1, "idp")

	test, provider := encryptedLogoutIDP(t)
	test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = old.Certificate, old.Key
	test.SP.IDPMetadata = test.IDP.Metadata()

	published := func() string {
		t.Helper()

		assert.NilError(t, test.IDP.CheckEncryptionKeys())

		encryption := encryptionKeyDescriptors(test.IDP.Metadata().IDPSSODescriptors[0].KeyDescriptors)
		assert.Assert(t, is.Len(encryption, 1))

		return encryption[0].KeyInfo.X509Data.X509Certificates[0].Data
	}

	// logout sends a LogoutRequest encrypted to the key of the metadata that the service provider holds, and
	// returns whether the identity provider could tell who it names.
	logout := func() bool {
		t.Helper()

		before := len(provider.lookups)
		status := encryptedLogoutBindings["post"](t, test, func(request *LogoutRequest) {
			assert.Assert(t, request.EncryptedID != nil)
		})
		assert.Check(t, is.Equal(StatusSuccess, status.StatusCode.Value))
		assert.Assert(t, is.Len(provider.lookups, before+1))

		return !provider.lookups[before].Unidentified
	}

	assert.Check(t, is.Equal(encodeCertificate(old.Certificate), published()))
	assert.Check(t, logout())

	// 1. The next key is loaded. It is not published, and what is encrypted to it is already decrypted, as another
	// instance of the identity provider may publish it first.
	test.IDP.DecryptionKeys = []DecryptionKey{next}
	stale := test.SP.IDPMetadata

	assert.Check(t, is.Equal(encodeCertificate(old.Certificate), published()))
	assert.Check(t, !strings.Contains(metadataString(t, &test.IDP), encodeCertificate(next.Certificate)))
	assert.Check(t, logout())

	// 2. The switch. The service provider still holds the old metadata, and is still understood.
	test.IDP.EncryptionCertificate, test.IDP.EncryptionKey = next.Certificate, next.Key
	test.IDP.DecryptionKeys = []DecryptionKey{old}

	assert.Check(t, is.Equal(encodeCertificate(next.Certificate), published()))
	assert.Check(t, !strings.Contains(metadataString(t, &test.IDP), encodeCertificate(old.Certificate)))
	assert.Check(t, logout())

	// It refreshes the metadata, and encrypts to the next key.
	test.SP.IDPMetadata = test.IDP.Metadata()

	assert.Check(t, logout())

	// 3. The old key is retired. A service provider with the current metadata is not affected, and one which
	// still encrypts to the old key no longer names anybody.
	test.IDP.DecryptionKeys = nil

	assert.Check(t, is.Equal(encodeCertificate(next.Certificate), published()))
	assert.Check(t, logout())

	test.SP.IDPMetadata = stale

	assert.Check(t, !logout())
}

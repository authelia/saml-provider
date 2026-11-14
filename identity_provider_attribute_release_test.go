package saml

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const (
	uriAttrNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

	mailAttributeName        = "urn:oid:0.9.2342.19200300.100.1.3"
	uidAttributeName         = "urn:oid:0.9.2342.19200300.100.1.1"
	affiliationAttributeName = "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
)

type attributeReleasePolicyFunc func(*IdpAuthnRequest, *Session, []Attribute) ([]Attribute, error)

func (f attributeReleasePolicyFunc) ReleaseAttributes(req *IdpAuthnRequest, session *Session, candidates []Attribute) ([]Attribute, error) {
	return f(req, session, candidates)
}

// releaseEveryAttribute releases every candidate, for tests of how attributes are stated rather than
// which are released.
var releaseEveryAttribute = attributeReleasePolicyFunc(func(_ *IdpAuthnRequest, _ *Session, candidates []Attribute) ([]Attribute, error) {
	return candidates, nil
})

// attributeReleaseSession returns a session with a value for every attribute that
// DefaultAssertionMaker can release.
func attributeReleaseSession() *Session {
	return &Session{
		ID:                     "f00df00df00d",
		NameID:                 "alice",
		UserName:               "alice",
		UserEmail:              "alice@example.com",
		UserCommonName:         "Alice Smith",
		UserSurname:            "Smith",
		UserGivenName:          "Alice",
		UserScopedAffiliation:  "member@example.com",
		EduPersonPrincipalName: "alice@example.com",
		SubjectID:              "alice@example.com",
		Groups:                 []string{"Users", "Administrators"},
		CustomAttributes: []Attribute{{
			Name:   "employeeNumber",
			Values: []AttributeValue{{Type: "xs:string", Value: "42"}},
		}},
	}
}

// attributeReleaseRequest returns a request from the test service provider, whose metadata lists
// services. index is the AttributeConsumingServiceIndex of the request.
func attributeReleaseRequest(t *testing.T, test *IdentityProviderTest, index string, services ...AttributeConsumingService) *IdpAuthnRequest {
	t.Helper()
	metadata := test.SP.Metadata()
	metadata.SPSSODescriptors[0].AttributeConsumingServices = services
	req := &IdpAuthnRequest{
		IDP:                     &test.IDP,
		Now:                     TimeNow(),
		ServiceProviderMetadata: metadata,
		SPSSODescriptor:         &metadata.SPSSODescriptors[0],
		ACSEndpoint:             &metadata.SPSSODescriptors[0].AssertionConsumerServices[0],
		Request:                 AuthnRequest{ID: "id-1", AttributeConsumingServiceIndex: index},
	}
	req.HTTPRequest, _ = http.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", nil)
	return req
}

func requested(name, nameFormat string, values ...string) RequestedAttribute {
	attribute := RequestedAttribute{Attribute: Attribute{Name: name, NameFormat: nameFormat}}
	for _, value := range values {
		attribute.Values = append(attribute.Values, AttributeValue{Type: "xs:string", Value: value})
	}
	return attribute
}

func service(index int, isDefault *bool, attributes ...RequestedAttribute) AttributeConsumingService {
	return AttributeConsumingService{
		Index:               index,
		IsDefault:           isDefault,
		ServiceNames:        []LocalizedName{{Lang: "en", Value: "service"}},
		RequestedAttributes: attributes,
	}
}

// releasedAttributes makes an assertion for req and returns the attributes it releases.
func releasedAttributes(t *testing.T, req *IdpAuthnRequest, session *Session) []Attribute {
	t.Helper()
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, session))
	switch len(req.Assertion.AttributeStatements) {
	case 0:
		return nil
	case 1:
		assert.Assert(t, len(req.Assertion.AttributeStatements[0].Attributes) != 0, "empty AttributeStatement")
		return req.Assertion.AttributeStatements[0].Attributes
	default:
		t.Fatalf("expected at most one AttributeStatement, got %d", len(req.Assertion.AttributeStatements))
		return nil
	}
}

func attributeNames(attributes []Attribute) []string {
	names := make([]string, 0, len(attributes))
	for _, attribute := range attributes {
		names = append(names, attribute.Name)
	}
	return names
}

func TestDefaultAttributeReleasePolicyReleasesNothingUnrequested(t *testing.T) {
	for name, services := range map[string][]AttributeConsumingService{
		"no service":                    nil,
		"service without any attribute": {service(0, nil)},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			req := attributeReleaseRequest(t, test, "", services...)
			assert.Check(t, is.Len(releasedAttributes(t, req, attributeReleaseSession()), 0))
			assert.Check(t, is.Len(req.Assertion.AttributeStatements, 0))
			assert.Check(t, is.Equal(req.Assertion.Subject.NameID.Value, "alice"))
		})
	}
}

func TestDefaultAttributeReleasePolicyReleasesOnlyRequested(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := attributeReleaseRequest(t, test, "", service(0, nil,
		requested(affiliationAttributeName, uriAttrNameFormat),
		requested(mailAttributeName, uriAttrNameFormat),
		requested("urn:oid:2.16.840.1.113730.3.1.241", uriAttrNameFormat), // displayName, which the session lacks
	))

	attributes := releasedAttributes(t, req, attributeReleaseSession())
	assert.Check(t, is.DeepEqual(attributeNames(attributes), []string{mailAttributeName, affiliationAttributeName}))
	assert.Check(t, is.DeepEqual(attributes[0], Attribute{
		FriendlyName: "mail",
		Name:         mailAttributeName,
		NameFormat:   uriAttrNameFormat,
		Values:       []AttributeValue{{Type: "xs:string", Value: "alice@example.com"}},
	}))
}

func TestDefaultAttributeReleasePolicyReleasesRequestedCustomAttributes(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := attributeReleaseRequest(t, test, "", service(0, nil, requested("employeeNumber", "")))
	assert.Check(t, is.DeepEqual(attributeNames(releasedAttributes(t, req, attributeReleaseSession())), []string{"employeeNumber"}))
}

// TestDefaultAttributeReleasePolicyMatchesNameFormat checks that an omitted NameFormat is unspecified,
// as SAMLCore §2.7.3.1 and errata E89 say, and that unspecified is compatible with any format.
func TestDefaultAttributeReleasePolicyMatchesNameFormat(t *testing.T) {
	for name, tc := range map[string]struct {
		requested RequestedAttribute
		released  bool
	}{
		"same format":              {requested(mailAttributeName, uriAttrNameFormat), true},
		"omitted format":           {requested(mailAttributeName, ""), true},
		"unspecified format":       {requested(mailAttributeName, unspecifiedAttrNameFormat), true},
		"other format":             {requested(mailAttributeName, basicAttrNameFormat), false},
		"name differs in case":     {requested(strings.ToUpper(mailAttributeName), uriAttrNameFormat), false},
		"custom attribute any fmt": {requested("employeeNumber", uriAttrNameFormat), true},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			req := attributeReleaseRequest(t, test, "", service(0, nil, tc.requested))
			attributes := releasedAttributes(t, req, attributeReleaseSession())
			if tc.released {
				assert.Check(t, is.DeepEqual(attributeNames(attributes), []string{tc.requested.Name}))
			} else {
				assert.Check(t, is.Len(attributes, 0))
			}
		})
	}
}

// TestDefaultAttributeReleasePolicyIgnoresFriendlyName checks that FriendlyName doesn't identify an
// attribute, as SAMLCore §2.7.3.1 forbids.
func TestDefaultAttributeReleasePolicyIgnoresFriendlyName(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	byFriendlyName := requested("urn:example:mail", uriAttrNameFormat)
	byFriendlyName.FriendlyName = "mail"
	req := attributeReleaseRequest(t, test, "", service(0, nil, byFriendlyName))
	assert.Check(t, is.Len(releasedAttributes(t, req, attributeReleaseSession()), 0))
}

// TestDefaultAttributeReleasePolicyReleasesRequestedValues checks that only the values listed by a
// RequestedAttribute are released, as SAMLMeta §2.4.4.2 says only they are relevant to the service.
func TestDefaultAttributeReleasePolicyReleasesRequestedValues(t *testing.T) {
	t.Run("matching value", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(affiliationAttributeName, uriAttrNameFormat, "Administrators", "Nobody")))
		attributes := releasedAttributes(t, req, attributeReleaseSession())
		assert.Assert(t, is.Len(attributes, 1))
		assert.Check(t, is.DeepEqual(attributes[0].Values, []AttributeValue{{Type: "xs:string", Value: "Administrators"}}))
	})

	t.Run("no matching value", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(affiliationAttributeName, uriAttrNameFormat, "Nobody")))
		assert.Check(t, is.Len(releasedAttributes(t, req, attributeReleaseSession()), 0))
	})
}

// TestDefaultAssertionMakerReleasesEmailUnderRequestedName checks the attributes that a service
// provider may request under its own name, such as "email".
func TestDefaultAssertionMakerReleasesEmailUnderRequestedName(t *testing.T) {
	for name, tc := range map[string]struct {
		requested RequestedAttribute
		value     string
	}{
		"basic":             {requested("email", basicAttrNameFormat), "alice@example.com"},
		"omitted format":    {requested("Email", ""), "alice@example.com"},
		"unspecified":       {requested("EmailAddress", unspecifiedAttrNameFormat), "alice@example.com"},
		"mixed case":        {requested("First_Name", basicAttrNameFormat), "Alice"},
		"common name":       {requested("FullName", basicAttrNameFormat), "Alice Smith"},
		"surname":           {requested("lastName", basicAttrNameFormat), "Smith"},
		"user":              {requested("UserID", basicAttrNameFormat), "alice"},
		"uri format":        {requested("email", uriAttrNameFormat), ""},
		"unknown attribute": {requested("shoe_size", basicAttrNameFormat), ""},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			req := attributeReleaseRequest(t, test, "", service(0, nil, tc.requested))
			attributes := releasedAttributes(t, req, attributeReleaseSession())
			if tc.value == "" {
				assert.Check(t, is.Len(attributes, 0))
				return
			}
			assert.Check(t, is.DeepEqual(attributes, []Attribute{{
				Name:       tc.requested.Name,
				NameFormat: tc.requested.NameFormat,
				Values:     []AttributeValue{{Type: "xs:string", Value: tc.value}},
			}}))
		})
	}
}

func TestDefaultAssertionMakerOmitsEmptyRequestedNameAttributes(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := attributeReleaseRequest(t, test, "", service(0, nil,
		requested("email", basicAttrNameFormat),
		requested("first_name", basicAttrNameFormat),
		requested("uid", basicAttrNameFormat),
	))
	attributes := releasedAttributes(t, req, &Session{ID: "s", NameID: "alice", UserName: "alice"})
	assert.Check(t, is.DeepEqual(attributeNames(attributes), []string{"uid"}))
}

func TestDefaultAssertionMakerReleasesRequestedNameOnce(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := attributeReleaseRequest(t, test, "", service(0, nil,
		requested("email", basicAttrNameFormat),
		requested("email", basicAttrNameFormat),
	))
	assert.Check(t, is.Len(releasedAttributes(t, req, attributeReleaseSession()), 1))
}

// TestAttributeConsumingServiceDefault checks the default rules of SAMLMeta §2.4.4, as changed by
// errata E87.
func TestAttributeConsumingServiceDefault(t *testing.T) {
	yes, no := true, false
	for name, tc := range map[string]struct {
		services []AttributeConsumingService
		index    int
	}{
		"only service":                {[]AttributeConsumingService{service(4, nil)}, 4},
		"isDefault true":              {[]AttributeConsumingService{service(1, nil), service(2, &yes)}, 2},
		"skips isDefault false":       {[]AttributeConsumingService{service(1, &no), service(2, nil)}, 2},
		"first when all are not":      {[]AttributeConsumingService{service(1, &no), service(2, &no)}, 1},
		"true before omitted":         {[]AttributeConsumingService{service(1, nil), service(2, &no), service(3, &yes)}, 3},
		"first of several isDefaults": {[]AttributeConsumingService{service(1, &no), service(2, nil), service(3, nil)}, 2},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			got := attributeReleaseRequest(t, test, "", tc.services...).AttributeConsumingService()
			assert.Assert(t, got != nil)
			assert.Check(t, is.Equal(got.Index, tc.index))
		})
	}

	t.Run("none", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		assert.Check(t, attributeReleaseRequest(t, test, "").AttributeConsumingService() == nil)
	})

	t.Run("no SPSSODescriptor", func(t *testing.T) {
		assert.Check(t, (&IdpAuthnRequest{}).AttributeConsumingService() == nil)
	})
}

// TestAttributeConsumingServiceIndex checks that the service named by the AttributeConsumingServiceIndex
// of the request is used, as SAMLCore §3.4.1 describes, and that an index which doesn't name one of
// the services selects none, rather than the default.
func TestAttributeConsumingServiceIndex(t *testing.T) {
	yes := true
	services := []AttributeConsumingService{
		service(1, &yes, requested(mailAttributeName, uriAttrNameFormat)),
		service(2, nil, requested(uidAttributeName, uriAttrNameFormat)),
	}

	for name, tc := range map[string]struct {
		index    string
		released []string
	}{
		"no index":       {"", []string{mailAttributeName}},
		"default index":  {"1", []string{mailAttributeName}},
		"other index":    {"2", []string{uidAttributeName}},
		"leading zero":   {"02", []string{uidAttributeName}},
		"unknown index":  {"3", nil},
		"invalid index":  {"two", nil},
		"negative index": {"-1", nil},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			req := attributeReleaseRequest(t, test, tc.index, services...)
			attributes := releasedAttributes(t, req, attributeReleaseSession())
			if tc.released == nil {
				assert.Check(t, is.Len(attributes, 0))
				assert.Check(t, req.AttributeConsumingService() == nil)
				return
			}
			assert.Check(t, is.DeepEqual(attributeNames(attributes), tc.released))
		})
	}
}

func TestDefaultAssertionMakerUsesConfiguredAttributeReleasePolicy(t *testing.T) {
	t.Run("receives every candidate", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		var candidates []Attribute
		test.IDP.AttributeReleasePolicy = attributeReleasePolicyFunc(func(_ *IdpAuthnRequest, _ *Session, c []Attribute) ([]Attribute, error) {
			candidates = c
			return c, nil
		})
		req := attributeReleaseRequest(t, test, "")
		attributes := releasedAttributes(t, req, attributeReleaseSession())
		assert.Check(t, is.DeepEqual(attributeNames(candidates), []string{
			uidAttributeName,
			mailAttributeName,
			"urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			"urn:oid:2.5.4.4",
			"urn:oid:2.5.4.42",
			"urn:oid:2.5.4.3",
			"urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
			"employeeNumber",
			affiliationAttributeName,
			"urn:oasis:names:tc:SAML:attribute:subject-id",
		}))
		assert.Check(t, is.DeepEqual(attributes, candidates))
	})

	t.Run("releases nothing", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.AttributeReleasePolicy = attributeReleasePolicyFunc(func(*IdpAuthnRequest, *Session, []Attribute) ([]Attribute, error) {
			return nil, nil
		})
		req := attributeReleaseRequest(t, test, "", service(0, nil, requested(mailAttributeName, uriAttrNameFormat)))
		assert.Check(t, is.Len(releasedAttributes(t, req, attributeReleaseSession()), 0))
	})

	t.Run("refuses", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.AttributeReleasePolicy = attributeReleasePolicyFunc(func(*IdpAuthnRequest, *Session, []Attribute) ([]Attribute, error) {
			return nil, errors.New("refused")
		})
		req := attributeReleaseRequest(t, test, "")
		assert.Check(t, is.ErrorContains(DefaultAssertionMaker{}.MakeAssertion(req, attributeReleaseSession()), "refused"))
	})
}

// TestServeSSOReleasesAttributesOfRequestedService checks that the AttributeConsumingServiceIndex of a
// posted request selects the attributes which are released.
func TestServeSSOReleasesAttributesOfRequestedService(t *testing.T) {
	yes := true
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID != test.SP.MetadataURL.String() {
				return nil, os.ErrNotExist
			}
			metadata := test.SP.Metadata()
			metadata.SPSSODescriptors[0].AttributeConsumingServices = []AttributeConsumingService{
				service(1, &yes, requested(mailAttributeName, uriAttrNameFormat)),
				service(2, nil, requested(uidAttributeName, uriAttrNameFormat)),
			}
			return metadata, nil
		},
	}
	session := attributeReleaseSession()
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session { return session },
	}
	var released []Attribute
	test.IDP.AttributeReleasePolicy = attributeReleasePolicyFunc(func(req *IdpAuthnRequest, session *Session, candidates []Attribute) ([]Attribute, error) {
		var err error
		released, err = DefaultAttributeReleasePolicy{}.ReleaseAttributes(req, session, candidates)
		return released, err
	})

	request, err := test.SP.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	request.AttributeConsumingServiceIndex = "2"
	doc := etree.NewDocument()
	doc.SetRoot(request.Element())
	body, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(body)}}
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)
	assert.Assert(t, is.Equal(w.Code, http.StatusOK), "body: %s", w.Body.String())
	_, response := postedResponse(t, w.Body.String())
	assert.Check(t, is.Equal(response.Status.StatusCode.Value, StatusSuccess))
	assert.Check(t, is.DeepEqual(attributeNames(released), []string{uidAttributeName}))
}

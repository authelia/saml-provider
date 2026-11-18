package saml

import (
	"encoding/xml"
	"math"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func scopingInt(v int) *int { return &v }

func scopingXML(t *testing.T, el *etree.Element) string {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(el)

	x, err := doc.WriteToString()
	assert.NilError(t, err)

	return x
}

const scopingProtocolNS = ` xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`

// scopingParse unmarshals a Scoping element which declares the samlp prefix.
func scopingParse(x string) (Scoping, error) {
	var scoping Scoping

	err := xml.Unmarshal([]byte(x), &scoping)

	return scoping, err
}

func TestScopingElement(t *testing.T) {
	testCases := []struct {
		name     string
		scoping  Scoping
		expected string
	}{
		{"empty", Scoping{}, `<samlp:Scoping/>`},
		{"proxy count zero", Scoping{ProxyCount: scopingInt(0)}, `<samlp:Scoping ProxyCount="0"/>`},
		{"proxy count", Scoping{ProxyCount: scopingInt(2)}, `<samlp:Scoping ProxyCount="2"/>`},
		{
			"requester IDs",
			Scoping{RequesterIDs: []string{"https://sp.example.com/", "https://proxy.example.com/"}},
			`<samlp:Scoping><samlp:RequesterID>https://sp.example.com/</samlp:RequesterID><samlp:RequesterID>https://proxy.example.com/</samlp:RequesterID></samlp:Scoping>`,
		},
		{
			"IDP list",
			Scoping{IDPList: &IDPList{IDPEntries: []IDPEntry{{ProviderID: "https://idp.example.com/"}}}},
			`<samlp:Scoping><samlp:IDPList><samlp:IDPEntry ProviderID="https://idp.example.com/"/></samlp:IDPList></samlp:Scoping>`,
		},
		{
			"everything, in the order of the schema",
			Scoping{
				ProxyCount: scopingInt(1),
				IDPList: &IDPList{
					IDPEntries: []IDPEntry{
						{ProviderID: "https://idp.example.com/", Name: "Example", Loc: "https://idp.example.com/sso"},
						{ProviderID: "https://other.example.com/"},
					},
					GetComplete: "https://sp.example.com/idplist",
				},
				RequesterIDs: []string{"https://sp.example.com/"},
			},
			`<samlp:Scoping ProxyCount="1"><samlp:IDPList>` +
				`<samlp:IDPEntry ProviderID="https://idp.example.com/" Name="Example" Loc="https://idp.example.com/sso"/>` +
				`<samlp:IDPEntry ProviderID="https://other.example.com/"/>` +
				`<samlp:GetComplete>https://sp.example.com/idplist</samlp:GetComplete></samlp:IDPList>` +
				`<samlp:RequesterID>https://sp.example.com/</samlp:RequesterID></samlp:Scoping>`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			el := tc.scoping.Element()
			assert.Check(t, is.Equal(scopingXML(t, el), tc.expected))

			// What is written is read back as the same value.
			el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")

			actual, err := scopingParse(scopingXML(t, el))
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(actual, tc.scoping))
		})
	}
}

func TestScopingUnmarshalAnyPrefix(t *testing.T) {
	scoping, err := scopingParse(`<Scoping xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ProxyCount="+3">` +
		`<IDPList><IDPEntry ProviderID=" https://idp.example.com/ " Name="An IdP"/><GetComplete> https://sp.example.com/list </GetComplete></IDPList>` +
		`<RequesterID>
			https://sp.example.com/
		</RequesterID></Scoping>`)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(scoping, Scoping{
		ProxyCount: scopingInt(3),
		IDPList: &IDPList{
			IDPEntries:  []IDPEntry{{ProviderID: "https://idp.example.com/", Name: "An IdP"}},
			GetComplete: "https://sp.example.com/list",
		},
		RequesterIDs: []string{"https://sp.example.com/"},
	}))
}

func TestScopingUnmarshalIgnoresOtherNamespaces(t *testing.T) {
	scoping, err := scopingParse(`<samlp:Scoping` + scopingProtocolNS + ` xmlns:x="urn:x">` +
		`<x:IDPList/><x:RequesterID>https://x.example.com/</x:RequesterID></samlp:Scoping>`)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(scoping, Scoping{}))
}

func TestScopingProxyCountSaturates(t *testing.T) {
	scoping, err := scopingParse(`<samlp:Scoping` + scopingProtocolNS + ` ProxyCount="99999999999999999999999999"/>`)
	assert.NilError(t, err)
	assert.Assert(t, scoping.ProxyCount != nil)
	assert.Check(t, is.Equal(*scoping.ProxyCount, math.MaxInt))
}

func TestScopingUnmarshalRejectsMalformed(t *testing.T) {
	entry := `<samlp:IDPEntry ProviderID="https://idp.example.com/"/>`

	testCases := []struct {
		name string
		xml  string
		err  string
	}{
		{"negative count", `<samlp:Scoping` + scopingProtocolNS + ` ProxyCount="-1"/>`, "ProxyCount"},
		{"negative zero count", `<samlp:Scoping` + scopingProtocolNS + ` ProxyCount="-0"/>`, "ProxyCount"},
		{"empty count", `<samlp:Scoping` + scopingProtocolNS + ` ProxyCount=""/>`, "ProxyCount"},
		{"sign only", `<samlp:Scoping` + scopingProtocolNS + ` ProxyCount="+"/>`, "ProxyCount"},
		{"fraction", `<samlp:Scoping` + scopingProtocolNS + ` ProxyCount="1.0"/>`, "ProxyCount"},
		{"hexadecimal", `<samlp:Scoping` + scopingProtocolNS + ` ProxyCount="0x1"/>`, "ProxyCount"},
		{"word", `<samlp:Scoping` + scopingProtocolNS + ` ProxyCount="one"/>`, "ProxyCount"},
		{"count with a space inside", `<samlp:Scoping` + scopingProtocolNS + ` ProxyCount="1 0"/>`, "ProxyCount"},
		{"two lists", `<samlp:Scoping` + scopingProtocolNS + `><samlp:IDPList>` + entry + `</samlp:IDPList><samlp:IDPList>` + entry + `</samlp:IDPList></samlp:Scoping>`, "more than one IDPList"},
		{"empty list", `<samlp:Scoping` + scopingProtocolNS + `><samlp:IDPList/></samlp:Scoping>`, "no IDPEntry"},
		{"list of only GetComplete", `<samlp:Scoping` + scopingProtocolNS + `><samlp:IDPList><samlp:GetComplete>https://sp.example.com/</samlp:GetComplete></samlp:IDPList></samlp:Scoping>`, "no IDPEntry"},
		{"entry without ProviderID", `<samlp:Scoping` + scopingProtocolNS + `><samlp:IDPList><samlp:IDPEntry Name="x"/></samlp:IDPList></samlp:Scoping>`, "ProviderID"},
		{"entry with blank ProviderID", `<samlp:Scoping` + scopingProtocolNS + `><samlp:IDPList><samlp:IDPEntry ProviderID=" "/></samlp:IDPList></samlp:Scoping>`, "ProviderID"},
		{"two GetComplete", `<samlp:Scoping` + scopingProtocolNS + `><samlp:IDPList>` + entry + `<samlp:GetComplete>https://a.example.com/</samlp:GetComplete><samlp:GetComplete>https://b.example.com/</samlp:GetComplete></samlp:IDPList></samlp:Scoping>`, "more than one GetComplete"},
		{"empty GetComplete", `<samlp:Scoping` + scopingProtocolNS + `><samlp:IDPList>` + entry + `<samlp:GetComplete/></samlp:IDPList></samlp:Scoping>`, "GetComplete"},
		{"empty RequesterID", `<samlp:Scoping` + scopingProtocolNS + `><samlp:RequesterID/></samlp:Scoping>`, "RequesterID"},
		{"blank RequesterID", `<samlp:Scoping` + scopingProtocolNS + `><samlp:RequesterID>https://sp.example.com/</samlp:RequesterID><samlp:RequesterID> </samlp:RequesterID></samlp:Scoping>`, "RequesterID"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scopingParse(tc.xml)
			assert.Check(t, is.ErrorContains(err, tc.err))
		})
	}
}

func TestIDPListContains(t *testing.T) {
	var none *IDPList

	assert.Check(t, !none.Contains("https://idp.example.com/"))

	list := &IDPList{IDPEntries: []IDPEntry{{ProviderID: "https://other.example.com/"}, {ProviderID: "https://idp.example.com/"}}}
	assert.Check(t, list.Contains("https://idp.example.com/"))
	assert.Check(t, !list.Contains("https://idp.example.com"))
	assert.Check(t, !list.Contains(""))
}

func TestAuthnRequestScopingXMLRoundTrip(t *testing.T) {
	issueInstant := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	expected := AuthnRequest{
		ID:           "id-1",
		Version:      "2.0",
		IssueInstant: issueInstant,
		Issuer:       &Issuer{Value: "https://sp.example.com/"},
		RequestedAuthnContext: &RequestedAuthnContext{
			Comparison:            "exact",
			AuthnContextClassRefs: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:Password"},
		},
		Scoping: &Scoping{
			ProxyCount:   scopingInt(0),
			IDPList:      &IDPList{IDPEntries: []IDPEntry{{ProviderID: "https://idp.example.com/"}}},
			RequesterIDs: []string{"https://first.example.com/", "https://second.example.com/"},
		},
	}

	x := scopingXML(t, expected.Element())

	// Scoping is the last child, after RequestedAuthnContext (SAMLCore §3.4.1).
	assert.Check(t, is.Contains(x, `</samlp:RequestedAuthnContext><samlp:Scoping ProxyCount="0">`))
	assert.Check(t, is.Contains(x, `</samlp:Scoping></samlp:AuthnRequest>`))

	var actual AuthnRequest
	assert.NilError(t, xml.Unmarshal([]byte(x), &actual))
	assert.Check(t, is.DeepEqual(actual.Scoping, expected.Scoping))

	expected.Scoping = nil

	x = scopingXML(t, expected.Element())
	assert.Check(t, !is.Contains(x, "Scoping")().Success())

	actual = AuthnRequest{}
	assert.NilError(t, xml.Unmarshal([]byte(x), &actual))
	assert.Check(t, actual.Scoping == nil)
}

// TestProxyRestrictionXMLRoundTrip shows what was wrong with ProxyRestriction: its fields had no tags, so the
// element that Element writes, which is the one of the schema, was parsed as an empty restriction.
func TestProxyRestrictionXMLRoundTrip(t *testing.T) {
	testCases := []struct {
		name        string
		restriction ProxyRestriction
		expected    string
	}{
		{"empty", ProxyRestriction{}, `<saml:ProxyRestriction/>`},
		{"count zero", ProxyRestriction{Count: scopingInt(0)}, `<saml:ProxyRestriction Count="0"/>`},
		{
			"count and audiences",
			ProxyRestriction{Count: scopingInt(2), Audiences: []Audience{{Value: "https://a.example.com/"}, {Value: "https://b.example.com/"}}},
			`<saml:ProxyRestriction Count="2"><saml:Audience>https://a.example.com/</saml:Audience><saml:Audience>https://b.example.com/</saml:Audience></saml:ProxyRestriction>`,
		},
		{
			"audiences",
			ProxyRestriction{Audiences: []Audience{{Value: "https://a.example.com/"}}},
			`<saml:ProxyRestriction><saml:Audience>https://a.example.com/</saml:Audience></saml:ProxyRestriction>`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			el := tc.restriction.Element()
			assert.Check(t, is.Equal(scopingXML(t, el), tc.expected))

			el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")

			var actual ProxyRestriction
			assert.NilError(t, xml.Unmarshal([]byte(scopingXML(t, el)), &actual))
			assert.Check(t, is.DeepEqual(actual, tc.restriction))
		})
	}
}

func TestConditionsProxyRestrictionXMLRoundTrip(t *testing.T) {
	expected := Conditions{
		NotBefore:            time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
		NotOnOrAfter:         time.Date(2026, 11, 18, 12, 5, 0, 0, time.UTC),
		AudienceRestrictions: []AudienceRestriction{{Audiences: []Audience{{Value: "https://sp.example.com/"}}}},
		ProxyRestriction:     &ProxyRestriction{Count: scopingInt(1), Audiences: []Audience{{Value: "https://sp.example.com/"}}},
	}

	el := expected.Element()
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")

	var actual Conditions
	assert.NilError(t, xml.Unmarshal([]byte(scopingXML(t, el)), &actual))
	assert.Check(t, is.DeepEqual(actual, expected))

	// encoding/xml writes the attribute and the elements of the schema too.
	marshalled, err := xml.Marshal(expected.ProxyRestriction)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(marshalled), `<ProxyRestriction Count="1"><Audience>https://sp.example.com/</Audience></ProxyRestriction>`))
}

func TestProxyRestrictionUnmarshalRejectsMalformedCount(t *testing.T) {
	for _, count := range []string{"-1", "", "x", "1.5"} {
		var restriction ProxyRestriction

		err := xml.Unmarshal([]byte(`<saml:ProxyRestriction xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Count="`+count+`"/>`), &restriction)
		assert.Check(t, is.ErrorContains(err, "Count"), "Count=%q", count)
	}
}

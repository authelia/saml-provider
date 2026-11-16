package saml

import (
	"encoding/xml"
	"io"
	"log"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
)

const (
	soapTestProtocolNS = "urn:oasis:names:tc:SAML:2.0:protocol"
	soapTestAssertNS   = "urn:oasis:names:tc:SAML:2.0:assertion"
	soapTestMessage    = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1" Version="2.0"/>`
	soapTestOtherNS    = "https://other.example.com/"
)

func soapTestEnvelope(header, body string) string {
	var sb strings.Builder

	sb.WriteString(`<soapenv:Envelope xmlns:soapenv="` + soapEnvelopeNS + `">`)

	if header != "" {
		sb.WriteString(`<soapenv:Header>` + header + `</soapenv:Header>`)
	}

	sb.WriteString(`<soapenv:Body>` + body + `</soapenv:Body></soapenv:Envelope>`)

	return sb.String()
}

func soapTestHeader(attrs string) string {
	return `<ex:Block xmlns:ex="` + soapTestOtherNS + `" ` + attrs + `/>`
}

func TestReadSOAPRequest(t *testing.T) {
	testCases := []struct {
		name        string
		contentType string
		body        string
		understood  []xml.Name
		fault       string
		headers     int
	}{
		{"ShouldAcceptValidEnvelope", "text/xml", soapTestEnvelope("", soapTestMessage), nil, "", 0},
		{"ShouldAcceptCharsetParameter", "text/xml; charset=utf-8", soapTestEnvelope("", soapTestMessage), nil, "", 0},
		{"ShouldRejectSOAP12ContentType", "application/soap+xml", soapTestEnvelope("", soapTestMessage), nil, "Client", 0},
		{"ShouldRejectMissingContentType", "", soapTestEnvelope("", soapTestMessage), nil, "Client", 0},
		{
			"ShouldRejectSOAP12Envelope", "text/xml",
			`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>` + soapTestMessage + `</s:Body></s:Envelope>`,
			nil, "Client", 0,
		},
		{
			"ShouldRejectMissingBody", "text/xml",
			`<soapenv:Envelope xmlns:soapenv="` + soapEnvelopeNS + `"></soapenv:Envelope>`, nil, "Client", 0,
		},
		{"ShouldRejectTwoBodyChildren", "text/xml", soapTestEnvelope("", soapTestMessage+soapTestMessage), nil, "Client", 0},
		{"ShouldRejectTextOnlyBody", "text/xml", soapTestEnvelope("", "text"), nil, "Client", 0},
		{
			"ShouldRejectOversizedBody", "text/xml",
			soapTestEnvelope("", soapTestMessage+"<!--"+strings.Repeat("a", soapMaxMessageSize)+"-->"), nil, "Client", 0,
		},
		{"ShouldRejectMalformedXML", "text/xml", `<soapenv:Envelope`, nil, "Client", 0},
		{
			"ShouldRejectXRVFailure", "text/xml",
			soapTestEnvelope("", soapTestMessage+`<!-- a -- b -->`), nil, "Client", 0,
		},
		{
			"ShouldRejectMustUnderstandNoActor", "text/xml",
			soapTestEnvelope(soapTestHeader(`soapenv:mustUnderstand="1"`), soapTestMessage), nil, "MustUnderstand", 0,
		},
		{
			"ShouldRejectMustUnderstandActorNext", "text/xml",
			soapTestEnvelope(soapTestHeader(`soapenv:mustUnderstand="1" soapenv:actor="`+soapActorNext+`"`), soapTestMessage),
			nil, "MustUnderstand", 0,
		},
		{
			"ShouldIgnoreMustUnderstandOtherActor", "text/xml",
			soapTestEnvelope(soapTestHeader(`soapenv:mustUnderstand="1" soapenv:actor="`+soapTestOtherNS+`"`), soapTestMessage),
			nil, "", 1,
		},
		{
			"ShouldAcceptUnderstoodHeader", "text/xml",
			soapTestEnvelope(soapTestHeader(`soapenv:mustUnderstand="1"`), soapTestMessage),
			[]xml.Name{{Space: soapTestOtherNS, Local: "Block"}}, "", 1,
		},
		{
			"ShouldAcceptMustUnderstandZero", "text/xml",
			soapTestEnvelope(soapTestHeader(`soapenv:mustUnderstand="0"`), soapTestMessage), nil, "", 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", strings.NewReader(tc.body))

			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}

			req, fault := readSOAPRequest(r, tc.understood...)

			if tc.fault != "" {
				assert.Assert(t, fault != nil)
				assert.Equal(t, fault.Code, tc.fault)
				assert.Assert(t, fault.String != "")
				assert.Assert(t, req == nil)

				return
			}

			assert.Assert(t, fault == nil)
			assert.Assert(t, req != nil)
			assert.Equal(t, req.Message.Tag, "LogoutRequest")
			assert.Equal(t, req.Message.NamespaceURI(), soapTestProtocolNS)
			assert.Equal(t, len(req.Headers), tc.headers)
		})
	}
}

func TestReadSOAPRequestInheritedNamespaces(t *testing.T) {
	t.Run("ShouldCarryPrefixesDeclaredOnEnvelope", func(t *testing.T) {
		body := `<soapenv:Envelope xmlns:soapenv="` + soapEnvelopeNS + `" xmlns:samlp="` + soapTestProtocolNS +
			`" xmlns:saml="` + soapTestAssertNS + `"><soapenv:Body><samlp:LogoutRequest ID="id-1" Version="2.0">` +
			`<saml:Issuer>https://sp.example.com</saml:Issuer></samlp:LogoutRequest></soapenv:Body></soapenv:Envelope>`

		r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", strings.NewReader(body))
		r.Header.Set("Content-Type", "text/xml")

		req, fault := readSOAPRequest(r)
		assert.Assert(t, fault == nil)

		var lr LogoutRequest

		assert.NilError(t, xml.Unmarshal(req.Body, &lr))
		assert.Equal(t, lr.Issuer.Value, "https://sp.example.com")

		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(req.Body))

		root := doc.Root()
		assert.Equal(t, root.SelectAttrValue("xmlns:samlp", ""), soapTestProtocolNS)
		assert.Equal(t, root.SelectAttrValue("xmlns:saml", ""), soapTestAssertNS)
		assert.Equal(t, root.SelectAttr("xmlns:soapenv") != nil, true)
	})

	t.Run("ShouldCarryDefaultNamespaceDeclaredOnBody", func(t *testing.T) {
		body := `<soapenv:Envelope xmlns:soapenv="` + soapEnvelopeNS + `"><soapenv:Body xmlns="` + soapTestProtocolNS +
			`"><LogoutRequest ID="id-1" Version="2.0"/></soapenv:Body></soapenv:Envelope>`

		r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", strings.NewReader(body))
		r.Header.Set("Content-Type", "text/xml")

		req, fault := readSOAPRequest(r)
		assert.Assert(t, fault == nil)
		assert.Equal(t, req.Message.NamespaceURI(), soapTestProtocolNS)

		var lr LogoutRequest

		assert.NilError(t, xml.Unmarshal(req.Body, &lr))
		assert.Equal(t, lr.ID, "id-1")
	})

	t.Run("ShouldPreferNearestDeclaration", func(t *testing.T) {
		body := `<soapenv:Envelope xmlns:soapenv="` + soapEnvelopeNS + `" xmlns:p="urn:far"><soapenv:Body xmlns:p="urn:near">` +
			`<p:Thing/></soapenv:Body></soapenv:Envelope>`

		r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", strings.NewReader(body))
		r.Header.Set("Content-Type", "text/xml")

		req, fault := readSOAPRequest(r)
		assert.Assert(t, fault == nil)
		assert.Equal(t, req.Message.NamespaceURI(), "urn:near")
	})
}

func TestReceiveSOAPRequestMethod(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.Logger = log.New(io.Discard, "", 0)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/slo", nil)

	req, ok := test.IDP.receiveSOAPRequest(w, r)
	assert.Assert(t, !ok)
	assert.Assert(t, req == nil)
	assert.Equal(t, w.Code, http.StatusMethodNotAllowed)
}

func TestReceiveSOAPRequestFault(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.Logger = log.New(io.Discard, "", 0)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", strings.NewReader("<bad"))
	r.Header.Set("Content-Type", "text/xml")

	_, ok := test.IDP.receiveSOAPRequest(w, r)
	assert.Assert(t, !ok)
	assert.Equal(t, w.Code, http.StatusInternalServerError)
	assert.Assert(t, strings.Contains(w.Body.String(), "soapenv:Client"))
}

func soapTestParseResponse(t *testing.T, w *httptest.ResponseRecorder) *etree.Element {
	t.Helper()

	res := w.Result()

	defer res.Body.Close()

	mt, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	assert.NilError(t, err)
	assert.Equal(t, mt, "text/xml")
	assert.Equal(t, res.Header.Get("Cache-Control"), "no-cache, no-store")
	assert.Equal(t, res.Header.Get("Pragma"), "no-cache")

	buf, err := io.ReadAll(res.Body)
	assert.NilError(t, err)

	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))

	root := doc.Root()
	assert.Equal(t, root.Tag, "Envelope")
	assert.Equal(t, root.NamespaceURI(), soapEnvelopeNS)

	return root
}

func TestWriteSOAPResponse(t *testing.T) {
	msg := etree.NewDocument()
	assert.NilError(t, msg.ReadFromString(soapTestMessage))

	t.Run("ShouldWriteBodyWithoutHeader", func(t *testing.T) {
		w := httptest.NewRecorder()
		assert.NilError(t, writeSOAPResponse(w, nil, msg.Root()))
		assert.Equal(t, w.Code, http.StatusOK)

		root := soapTestParseResponse(t, w)
		assert.Assert(t, root.SelectElement("Header") == nil)

		body := root.SelectElement("Body")
		assert.Assert(t, body != nil)
		assert.Equal(t, body.NamespaceURI(), soapEnvelopeNS)

		children := body.ChildElements()
		assert.Equal(t, len(children), 1)
		assert.Equal(t, children[0].Tag, "LogoutRequest")
		assert.Equal(t, children[0].NamespaceURI(), soapTestProtocolNS)
	})

	t.Run("ShouldWriteHeader", func(t *testing.T) {
		hdr := etree.NewDocument()
		assert.NilError(t, hdr.ReadFromString(`<ex:Block xmlns:ex="`+soapTestOtherNS+`"/>`))

		w := httptest.NewRecorder()
		assert.NilError(t, writeSOAPResponse(w, []*etree.Element{hdr.Root()}, msg.Root()))

		root := soapTestParseResponse(t, w)
		header := root.SelectElement("Header")
		assert.Assert(t, header != nil)
		assert.Equal(t, len(header.ChildElements()), 1)
		assert.Equal(t, header.ChildElements()[0].NamespaceURI(), soapTestOtherNS)
	})
}

func TestWriteSOAPFault(t *testing.T) {
	w := httptest.NewRecorder()
	writeSOAPFault(w, &soapFault{Code: "Client", String: "the request is not a SOAP 1.1 envelope"})

	assert.Equal(t, w.Code, http.StatusInternalServerError)

	root := soapTestParseResponse(t, w)
	children := root.SelectElement("Body").ChildElements()
	assert.Equal(t, len(children), 1)
	assert.Equal(t, children[0].Tag, "Fault")
	assert.Equal(t, children[0].NamespaceURI(), soapEnvelopeNS)
	assert.Equal(t, children[0].SelectElement("faultcode").Text(), "soapenv:Client")
	assert.Equal(t, children[0].SelectElement("faultstring").Text(), "the request is not a SOAP 1.1 envelope")
}

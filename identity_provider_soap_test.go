package saml

import (
	"encoding/xml"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
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
				require.NotNil(t, fault)
				require.Equal(t, fault.Code, tc.fault)
				require.True(t, fault.String != "")
				require.Nil(t, req)

				return
			}

			require.Nil(t, fault)
			require.NotNil(t, req)
			require.Equal(t, req.Message.Tag, "LogoutRequest")
			require.Equal(t, req.Message.NamespaceURI(), soapTestProtocolNS)
			require.Equal(t, len(req.Headers), tc.headers)
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
		require.Nil(t, fault)

		var lr LogoutRequest

		require.NoError(t, xml.Unmarshal(req.Body, &lr))
		require.Equal(t, lr.Issuer.Value, "https://sp.example.com")

		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromBytes(req.Body))

		root := doc.Root()
		require.Equal(t, root.SelectAttrValue("xmlns:samlp", ""), soapTestProtocolNS)
		require.Equal(t, root.SelectAttrValue("xmlns:saml", ""), soapTestAssertNS)
		require.Equal(t, root.SelectAttr("xmlns:soapenv") != nil, true)
	})

	t.Run("ShouldCarryDefaultNamespaceDeclaredOnBody", func(t *testing.T) {
		body := `<soapenv:Envelope xmlns:soapenv="` + soapEnvelopeNS + `"><soapenv:Body xmlns="` + soapTestProtocolNS +
			`"><LogoutRequest ID="id-1" Version="2.0"/></soapenv:Body></soapenv:Envelope>`

		r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", strings.NewReader(body))
		r.Header.Set("Content-Type", "text/xml")

		req, fault := readSOAPRequest(r)
		require.Nil(t, fault)
		require.Equal(t, req.Message.NamespaceURI(), soapTestProtocolNS)

		var lr LogoutRequest

		require.NoError(t, xml.Unmarshal(req.Body, &lr))
		require.Equal(t, lr.ID, "id-1")
	})

	t.Run("ShouldPreferNearestDeclaration", func(t *testing.T) {
		body := `<soapenv:Envelope xmlns:soapenv="` + soapEnvelopeNS + `" xmlns:p="urn:far"><soapenv:Body xmlns:p="urn:near">` +
			`<p:Thing/></soapenv:Body></soapenv:Envelope>`

		r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", strings.NewReader(body))
		r.Header.Set("Content-Type", "text/xml")

		req, fault := readSOAPRequest(r)
		require.Nil(t, fault)
		require.Equal(t, req.Message.NamespaceURI(), "urn:near")
	})
}

func TestReceiveSOAPRequestMethod(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.Observer = logObserver(io.Discard)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/slo", nil)

	req, ok := test.IDP.receiveSOAPRequest(w, r, EventLogout)
	require.False(t, ok)
	require.Nil(t, req)
	require.Equal(t, w.Code, http.StatusMethodNotAllowed)
}

func TestReceiveSOAPRequestFault(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.Observer = logObserver(io.Discard)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", strings.NewReader("<bad"))
	r.Header.Set("Content-Type", "text/xml")

	_, ok := test.IDP.receiveSOAPRequest(w, r, EventLogout)
	require.False(t, ok)
	require.Equal(t, w.Code, http.StatusInternalServerError)
	require.True(t, strings.Contains(w.Body.String(), "soapenv:Client"))
}

func soapTestParseResponse(t *testing.T, w *httptest.ResponseRecorder) *etree.Element {
	t.Helper()

	res := w.Result()

	defer res.Body.Close()

	mt, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	require.NoError(t, err)
	require.Equal(t, mt, "text/xml")
	require.Equal(t, res.Header.Get("Cache-Control"), "no-cache, no-store")
	require.Equal(t, res.Header.Get("Pragma"), "no-cache")

	buf, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(buf))

	root := doc.Root()
	require.Equal(t, root.Tag, "Envelope")
	require.Equal(t, root.NamespaceURI(), soapEnvelopeNS)

	return root
}

func TestWriteSOAPResponse(t *testing.T) {
	msg := etree.NewDocument()
	require.NoError(t, msg.ReadFromString(soapTestMessage))

	t.Run("ShouldWriteBodyWithoutHeader", func(t *testing.T) {
		w := httptest.NewRecorder()
		require.NoError(t, writeSOAPResponse(w, nil, msg.Root()))
		require.Equal(t, w.Code, http.StatusOK)

		root := soapTestParseResponse(t, w)
		require.Nil(t, root.SelectElement("Header"))

		body := root.SelectElement("Body")
		require.NotNil(t, body)
		require.Equal(t, body.NamespaceURI(), soapEnvelopeNS)

		children := body.ChildElements()
		require.Equal(t, len(children), 1)
		require.Equal(t, children[0].Tag, "LogoutRequest")
		require.Equal(t, children[0].NamespaceURI(), soapTestProtocolNS)
	})

	t.Run("ShouldWriteHeader", func(t *testing.T) {
		hdr := etree.NewDocument()
		require.NoError(t, hdr.ReadFromString(`<ex:Block xmlns:ex="`+soapTestOtherNS+`"/>`))

		w := httptest.NewRecorder()
		require.NoError(t, writeSOAPResponse(w, []*etree.Element{hdr.Root()}, msg.Root()))

		root := soapTestParseResponse(t, w)
		header := root.SelectElement("Header")
		require.NotNil(t, header)
		require.Equal(t, len(header.ChildElements()), 1)
		require.Equal(t, header.ChildElements()[0].NamespaceURI(), soapTestOtherNS)
	})
}

func TestWriteSOAPFault(t *testing.T) {
	w := httptest.NewRecorder()
	writeSOAPFault(w, &soapFault{Code: "Client", String: "the request is not a SOAP 1.1 envelope"})

	require.Equal(t, w.Code, http.StatusInternalServerError)

	root := soapTestParseResponse(t, w)
	children := root.SelectElement("Body").ChildElements()
	require.Equal(t, len(children), 1)
	require.Equal(t, children[0].Tag, "Fault")
	require.Equal(t, children[0].NamespaceURI(), soapEnvelopeNS)
	require.Equal(t, children[0].SelectElement("faultcode").Text(), "soapenv:Client")
	require.Equal(t, children[0].SelectElement("faultstring").Text(), "the request is not a SOAP 1.1 envelope")
}

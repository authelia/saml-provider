package saml

import (
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// childTags returns the tags of the child elements of el, in order.
func childTags(el *etree.Element) []string {
	children := el.ChildElements()
	tags := make([]string, 0, len(children))

	for _, child := range children {
		tags = append(tags, child.Tag)
	}

	return tags
}

// The elements are in the order of the schema of SAMLCore §3.6.1, and are read back as they were written.
func TestManageNameIDRequestElement(t *testing.T) {
	issueInstant := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)

	request := &ManageNameIDRequest{
		ID:           "id-1",
		Version:      "2.0",
		IssueInstant: issueInstant,
		Destination:  "https://idp.example.com/saml/mni",
		Consent:      "urn:oasis:names:tc:SAML:2.0:consent:unspecified",
		Issuer:       &Issuer{Value: "https://sp.example.com"},
		NameID:       &NameID{Format: string(PersistentNameIDFormat), Value: "p-1", SPProvidedID: "old"},
		NewID:        "new",
	}

	el := request.Element()
	assert.Check(t, is.Equal(el.NamespaceURI(), samlProtocolNS))
	assert.Check(t, is.DeepEqual(childTags(el), []string{"Issuer", "NameID", "NewID"}))

	var parsed ManageNameIDRequest
	assert.NilError(t, unmarshalElement(el, &parsed))
	assert.Check(t, is.Equal(parsed.ID, "id-1"))
	assert.Check(t, parsed.IssueInstant.Equal(issueInstant))
	assert.Check(t, is.Equal(parsed.Destination, request.Destination))
	assert.Check(t, is.Equal(parsed.Consent, request.Consent))
	assert.Check(t, is.DeepEqual(*parsed.NameID, *request.NameID))
	assert.Check(t, is.Equal(parsed.NewID, "new"))
	assert.Check(t, !parsed.Terminate)

	request.NewID, request.Terminate = "", true
	el = request.Element()
	assert.Check(t, is.DeepEqual(childTags(el), []string{"Issuer", "NameID", "Terminate"}))

	parsed = ManageNameIDRequest{}
	assert.NilError(t, unmarshalElement(el, &parsed))
	assert.Check(t, parsed.Terminate)
	assert.Check(t, is.Equal(parsed.NewID, ""))

	// A plaintext identifier is never written beside its ciphertext.
	request.EncryptedID, request.NewEncryptedID = etree.NewElement("saml:EncryptedID"), etree.NewElement("samlp:NewEncryptedID")
	assert.Check(t, is.DeepEqual(childTags(request.Element()), []string{"Issuer", "EncryptedID", "NewEncryptedID"}))
}

func TestManageNameIDResponseElement(t *testing.T) {
	response := &ManageNameIDResponse{
		ID:           "id-2",
		InResponseTo: "id-1",
		Version:      "2.0",
		IssueInstant: time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC),
		Destination:  "https://sp.example.com/mni",
		Issuer:       &Issuer{Value: "https://idp.example.com"},
		Status:       Status{StatusCode: StatusCode{Value: StatusRequester, StatusCode: &StatusCode{Value: StatusUnknownPrincipal}}},
	}

	el := response.Element()
	assert.Check(t, is.DeepEqual(childTags(el), []string{"Issuer", "Status"}))

	var parsed ManageNameIDResponse
	assert.NilError(t, unmarshalElement(el, &parsed))
	assert.Check(t, is.Equal(parsed.InResponseTo, "id-1"))
	assert.Check(t, is.Equal(parsed.Destination, response.Destination))
	assert.Check(t, is.Equal(parsed.Status.StatusCode.StatusCode.Value, StatusUnknownPrincipal))
}

// SAMLCore §3.8.1 and §3.8.2.
func TestNameIDMappingElements(t *testing.T) {
	format, target, allowCreate := string(PersistentNameIDFormat), "https://sp-b.example.com", true

	request := &NameIDMappingRequest{
		ID:           "id-1",
		Version:      "2.0",
		IssueInstant: time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC),
		Issuer:       &Issuer{Value: "https://sp.example.com"},
		NameID:       &NameID{Value: "p-1"},
		NameIDPolicy: &NameIDPolicy{Format: &format, SPNameQualifier: &target, AllowCreate: &allowCreate},
	}

	el := request.Element()
	assert.Check(t, is.DeepEqual(childTags(el), []string{"Issuer", "NameID", "NameIDPolicy"}))

	var parsed NameIDMappingRequest
	assert.NilError(t, unmarshalElement(el, &parsed))
	assert.Check(t, is.Equal(parsed.NameID.Value, "p-1"))
	assert.Check(t, is.Equal(*parsed.NameIDPolicy.Format, format))
	assert.Check(t, is.Equal(*parsed.NameIDPolicy.SPNameQualifier, target))
	assert.Check(t, *parsed.NameIDPolicy.AllowCreate)

	request.EncryptedID = etree.NewElement("saml:EncryptedID")
	assert.Check(t, is.DeepEqual(childTags(request.Element()), []string{"Issuer", "EncryptedID", "NameIDPolicy"}))

	response := &NameIDMappingResponse{
		ID:           "id-2",
		InResponseTo: "id-1",
		Version:      "2.0",
		IssueInstant: time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC),
		Issuer:       &Issuer{Value: "https://idp.example.com"},
		Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}},
		NameID:       &NameID{Value: "b-1"},
	}

	el = response.Element()
	assert.Check(t, is.DeepEqual(childTags(el), []string{"Issuer", "Status", "NameID"}))

	var parsedResponse NameIDMappingResponse
	assert.NilError(t, unmarshalElement(el, &parsedResponse))
	assert.Check(t, is.Equal(parsedResponse.NameID.Value, "b-1"))
	assert.Check(t, is.Equal(parsedResponse.InResponseTo, "id-1"))

	response.EncryptedID = etree.NewElement("saml:EncryptedID")
	assert.Check(t, is.DeepEqual(childTags(response.Element()), []string{"Issuer", "Status", "EncryptedID"}))

	// The schema requires an identifier, so a response without one has an empty NameID.
	response.NameID, response.EncryptedID = nil, nil
	el = response.Element()
	assert.Check(t, is.DeepEqual(childTags(el), []string{"Issuer", "Status", "NameID"}))
	assert.Check(t, is.Equal(el.FindElement("./NameID").Text(), ""))
}

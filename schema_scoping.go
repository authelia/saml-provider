package saml

import (
	"encoding/xml"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/beevik/etree"
)

// Scoping represents the SAML element Scoping, by which the requester of an AuthnRequest says which identity
// providers it accepts and how far the request may be proxied.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §3.4.1.2.
type Scoping struct {
	// ProxyCount is the number of identity providers that the request may be passed on to, between the one that
	// receives it and the one that authenticates the principal. Zero permits none, and nil, for no attribute, is
	// no restriction. A value that is too large for an int is read as the largest.
	ProxyCount *int `xml:",attr"`

	// IDPList is an advisory list of the identity providers that the requester accepts.
	IDPList *IDPList `xml:"urn:oasis:names:tc:SAML:2.0:protocol IDPList"`

	// RequesterIDs are the entity IDs of those on whose behalf the requester asks: the chain of requesters when
	// the request was proxied (SAMLCore §3.4.1.5). They are what the requester claims.
	RequesterIDs []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequesterID"`
}

// Element returns an etree.Element representing the object in XML form.
func (s *Scoping) Element() *etree.Element {
	el := etree.NewElement("samlp:Scoping")
	if s.ProxyCount != nil {
		el.CreateAttr("ProxyCount", strconv.Itoa(*s.ProxyCount))
	}

	if s.IDPList != nil {
		el.AddChild(s.IDPList.Element())
	}

	for _, requesterID := range s.RequesterIDs {
		el.CreateElement("samlp:RequesterID").SetText(requesterID)
	}

	return el
}

// UnmarshalXML implements [xml.Unmarshaler]. It returns an error for an element that the schema doesn't allow: a
// ProxyCount that is not a non-negative integer, more than one IDPList, or a RequesterID that is empty.
func (s *Scoping) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	aux := struct {
		ProxyCount   *string   `xml:",attr"`
		IDPLists     []IDPList `xml:"urn:oasis:names:tc:SAML:2.0:protocol IDPList"`
		RequesterIDs []string  `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequesterID"`
	}{}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	scoping := Scoping{}

	if aux.ProxyCount != nil {
		count, err := parseNonNegativeInteger(*aux.ProxyCount)
		if err != nil {
			return fmt.Errorf("the ProxyCount of the Scoping is %w", err)
		}

		scoping.ProxyCount = &count
	}

	switch len(aux.IDPLists) {
	case 0:
	case 1:
		scoping.IDPList = &aux.IDPLists[0]
	default:
		return errors.New("the Scoping has more than one IDPList")
	}

	for _, requesterID := range aux.RequesterIDs {
		requesterID = strings.TrimSpace(requesterID)
		if requesterID == "" {
			return errors.New("a RequesterID of the Scoping is empty")
		}

		scoping.RequesterIDs = append(scoping.RequesterIDs, requesterID)
	}

	*s = scoping

	return nil
}

// IDPList represents the SAML element IDPList, the identity providers that a requester accepts.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §3.4.1.3.
type IDPList struct {
	// IDPEntries are the identity providers, in the order the requester prefers them. There is at least one.
	IDPEntries []IDPEntry `xml:"urn:oasis:names:tc:SAML:2.0:protocol IDPEntry"`

	// GetComplete is where the complete list can be retrieved from, when IDPEntries is not all of it. The
	// identity provider never retrieves it.
	GetComplete string `xml:"urn:oasis:names:tc:SAML:2.0:protocol GetComplete,omitempty"`
}

// Element returns an etree.Element representing the object in XML form.
func (l *IDPList) Element() *etree.Element {
	el := etree.NewElement("samlp:IDPList")
	for i := range l.IDPEntries {
		el.AddChild(l.IDPEntries[i].Element())
	}

	if l.GetComplete != "" {
		el.CreateElement("samlp:GetComplete").SetText(l.GetComplete)
	}

	return el
}

// UnmarshalXML implements [xml.Unmarshaler]. It returns an error for an element that the schema doesn't allow: no
// IDPEntry, one without a ProviderID, or more than one GetComplete.
func (l *IDPList) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	aux := struct {
		IDPEntries []struct {
			ProviderID string `xml:",attr"`
			Name       string `xml:",attr"`
			Loc        string `xml:",attr"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:protocol IDPEntry"`
		GetCompletes []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol GetComplete"`
	}{}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	if len(aux.IDPEntries) == 0 {
		return errors.New("the IDPList has no IDPEntry")
	}

	list := IDPList{IDPEntries: make([]IDPEntry, 0, len(aux.IDPEntries))}

	for _, entry := range aux.IDPEntries {
		providerID := strings.TrimSpace(entry.ProviderID)
		if providerID == "" {
			return errors.New("an IDPEntry of the IDPList has no ProviderID")
		}

		list.IDPEntries = append(list.IDPEntries, IDPEntry{
			ProviderID: providerID,
			Name:       entry.Name,
			Loc:        strings.TrimSpace(entry.Loc),
		})
	}

	switch len(aux.GetCompletes) {
	case 0:
	case 1:
		if list.GetComplete = strings.TrimSpace(aux.GetCompletes[0]); list.GetComplete == "" {
			return errors.New("the GetComplete of the IDPList is empty")
		}
	default:
		return errors.New("the IDPList has more than one GetComplete")
	}

	*l = list

	return nil
}

// Contains reports whether the list names the identity provider with that entity ID. A list that has a
// GetComplete is not all of it, so false then doesn't mean that the requester excludes the identity provider.
func (l *IDPList) Contains(providerID string) bool {
	if l == nil {
		return false
	}

	for i := range l.IDPEntries {
		if l.IDPEntries[i].ProviderID == providerID {
			return true
		}
	}

	return false
}

// IDPEntry represents the SAML element IDPEntry, one identity provider of an IDPList.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §3.4.1.3.1.
type IDPEntry struct {
	// ProviderID is the entity ID of the identity provider.
	ProviderID string `xml:",attr"`

	// Name is a name of the identity provider for people to read.
	Name string `xml:",attr,omitempty"`

	// Loc is the location of the endpoint of the identity provider for authentication requests.
	Loc string `xml:",attr,omitempty"`
}

// Element returns an etree.Element representing the object in XML form.
func (e *IDPEntry) Element() *etree.Element {
	el := etree.NewElement("samlp:IDPEntry")
	el.CreateAttr("ProviderID", e.ProviderID)

	if e.Name != "" {
		el.CreateAttr("Name", e.Name)
	}

	if e.Loc != "" {
		el.CreateAttr("Loc", e.Loc)
	}

	return el
}

// parseNonNegativeInteger returns the value of an xs:nonNegativeInteger: decimal digits, which a plus sign may
// precede. The type has no largest value, so one that is too large for an int is the largest int. The error is
// worded to follow the name of what was parsed.
func parseNonNegativeInteger(s string) (int, error) {
	digits := strings.TrimPrefix(strings.TrimSpace(s), "+")
	if digits == "" {
		return 0, errors.New("not a non-negative integer")
	}

	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, errors.New("not a non-negative integer")
		}
	}

	value, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || value > math.MaxInt {
		return math.MaxInt, nil
	}

	return int(value), nil
}

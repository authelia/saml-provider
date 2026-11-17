package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// managedLogoutFixture is a propagationFixture whose service providers A and B were each asserted the persistent
// identifier alice in one session, whose NameIDProvider manages that identifier, and whose LogoutSessionProvider
// finds sessions with MatchesSession.
type managedLogoutFixture struct {
	*propagationFixture
	names *nameIDManagementProvider
}

func newManagedLogoutFixture(t *testing.T) *managedLogoutFixture {
	t.Helper()

	f := &managedLogoutFixture{propagationFixture: newPropagationFixture(t), names: &nameIDManagementProvider{known: []string{"alice"}}}

	idp := &f.test.IDP
	idp.SessionProvider = matchingLogoutSessionProvider{f.provider}
	idp.NameIDProvider = f.names
	idp.SOAPManageNameIDURL = mustParseURL(soapManageNameIDTestURL)

	return f
}

// asserted returns the NameID that sp was asserted for the session, as its participant records it.
func (f *managedLogoutFixture) asserted(sp *ServiceProvider) NameID {
	for _, participant := range f.provider.participants[f.session.ID] {
		if participant.ServiceProviderEntityID == sp.MetadataURL.String() {
			return participant.NameID
		}
	}

	panic("the service provider is not a participant")
}

// only leaves sp as the one participant of the session, so that its logout is answered without visiting another.
func (f *managedLogoutFixture) only(sp *ServiceProvider) {
	f.provider.participants[f.session.ID] = []SessionParticipant{{
		ServiceProviderEntityID: sp.MetadataURL.String(),
		NameID:                  f.asserted(sp),
		SessionIndex:            f.session.Index,
		IssueInstant:            TimeNow(),
	}}
}

// manage sends the signed ManageNameIDRequest of sp for its identifier over SOAP, as mutate changes it, and returns
// the status of the answer.
func (f *managedLogoutFixture) manage(t *testing.T, sp *ServiceProvider, mutate func(*ManageNameIDRequest)) Status {
	t.Helper()

	nameID := f.asserted(sp)

	el, _ := manageNameIDRequestElement(f.test, soapManageNameIDTestURL, manageNameIDOptions{mutate: func(request *ManageNameIDRequest) {
		request.Issuer.Value = sp.MetadataURL.String()
		request.NameID = &nameID

		mutate(request)
	}})

	w := httptest.NewRecorder()
	f.test.IDP.ServeSOAPManageNameID(w, nameIDTestSOAPPost(t, soapManageNameIDTestURL, signTestElement(t, sp, el)))

	response := &ManageNameIDResponse{}
	assert.NilError(t, unmarshalElement(nameIDTestSOAPMessage(t, w, "ManageNameIDResponse"), response))

	return response.Status
}

func newID(value string) func(*ManageNameIDRequest) {
	return func(request *ManageNameIDRequest) { request.NewID = value }
}

func terminateNameID(request *ManageNameIDRequest) {
	request.NewID, request.Terminate = "", true
}

// logout sends the signed LogoutRequest of sp for nameID, and returns the status of the answer.
func (f *managedLogoutFixture) logout(t *testing.T, sp *ServiceProvider, nameID NameID) Status {
	t.Helper()

	r, id := redirectLogoutRequest(t, sp, func(request *LogoutRequest) { request.NameID = &nameID })

	_, response := redirectedLogoutResponse(t, serveSLO(f.test, r))
	assert.Check(t, is.Equal(response.InResponseTo, id))

	return response.Status
}

// propagatedNameID returns the NameID of the LogoutRequest that the identity provider sent to location on the
// HTTP-Redirect binding.
func propagatedNameID(t *testing.T, location *url.URL) NameID {
	t.Helper()

	encoded, err := base64.StdEncoding.DecodeString(location.Query().Get("SAMLRequest"))
	assert.NilError(t, err)

	buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(encoded)))
	assert.NilError(t, err)

	var request LogoutRequest

	assert.NilError(t, xml.Unmarshal(buf, &request))
	assert.Assert(t, request.NameID != nil)

	return *request.NameID
}

// SAMLCore §3.6.3 as changed by errata E55, and §8.3.7: once the service provider has registered a NewID, it is
// the SPProvidedID of the identifier in what the two exchange. SAMLCore §3.7.3.2: the session is the one that
// the identifier of the LogoutRequest names, so a request with the SPProvidedID must still find the session that
// was established before it was registered, whose participant was recorded without it.
func TestLogoutRequestWithRegisteredSPProvidedIDEndsSession(t *testing.T) {
	withAlias := func(f *managedLogoutFixture, alias string) NameID {
		nameID := f.asserted(f.a)
		nameID.SPProvidedID = alias

		return nameID
	}

	t.Run("after NewID", func(t *testing.T) {
		f := newManagedLogoutFixture(t)
		f.only(f.a)

		checkStatus(t, f.manage(t, f.a, newID("a-alias")), StatusSuccess, "")

		// The participant is as it was recorded: the library looks the alias up, and doesn't rewrite records.
		assert.Check(t, is.Equal(f.asserted(f.a).SPProvidedID, ""))

		checkStatus(t, f.logout(t, f.a, withAlias(f, "a-alias")), StatusSuccess, "")
		assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
	})

	t.Run("through the NameID of the session", func(t *testing.T) {
		f := newManagedLogoutFixture(t)
		f.session.NameIDFormat = string(PersistentNameIDFormat)
		f.provider.participants[f.session.ID] = nil

		nameID := NameID{
			Format:          string(PersistentNameIDFormat),
			Value:           "alice",
			NameQualifier:   f.test.IDP.Metadata().EntityID,
			SPNameQualifier: f.a.MetadataURL.String(),
			SPProvidedID:    "a-alias",
		}

		// Nothing is registered yet, so the identifier is not one that the identity provider uses.
		f.logout(t, f.a, nameID)
		assert.Check(t, is.Len(f.provider.terminated, 0))

		f.names.aliases = map[string]string{aliasKey(f.a.MetadataURL.String(), "alice"): "a-alias"}

		checkStatus(t, f.logout(t, f.a, nameID), StatusSuccess, "")
		assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
	})

	t.Run("without the SPProvidedID", func(t *testing.T) {
		f := newManagedLogoutFixture(t)
		f.only(f.a)

		checkStatus(t, f.manage(t, f.a, newID("a-alias")), StatusSuccess, "")

		// The identifier as it was asserted for the session still names it, and the provider isn't asked.
		f.names.lookups = nil

		checkStatus(t, f.logout(t, f.a, f.asserted(f.a)), StatusSuccess, "")
		assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
		assert.Check(t, is.Len(f.names.lookups, 0))
	})

	for name, tc := range map[string]struct {
		registered, sent string
	}{
		"never registered":         {registered: "", sent: "a-alias"},
		"another SPProvidedID":     {registered: "a-alias", sent: "other"},
		"a replaced SPProvidedID":  {registered: "a-newer", sent: "a-alias"},
		"that of another provider": {registered: "", sent: "b-alias"},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			f := newManagedLogoutFixture(t)

			checkStatus(t, f.manage(t, f.b, newID("b-alias")), StatusSuccess, "")

			if tc.registered != "" {
				checkStatus(t, f.manage(t, f.a, newID("a-alias")), StatusSuccess, "")
				checkStatus(t, f.manage(t, f.a, newID(tc.registered)), StatusSuccess, "")
			}

			f.only(f.a)

			f.logout(t, f.a, withAlias(f, tc.sent))
			assert.Check(t, is.Len(f.provider.terminated, 0))
		})
	}

	t.Run("lookup fails", func(t *testing.T) {
		f := newManagedLogoutFixture(t)
		f.only(f.a)
		f.names.lookupErr = errors.New("directory unavailable")

		checkStatus(t, f.logout(t, f.a, withAlias(f, "a-alias")), StatusResponder, "")
		assert.Check(t, is.Len(f.provider.terminated, 0))
	})
}

// SAMLCore §3.6.3: the identity provider MUST include the NewID as the SPProvidedID when it subsequently
// communicates with the service provider using the identifier, which a propagated LogoutRequest does.
func TestPropagatedLogoutRequestCarriesRegisteredSPProvidedID(t *testing.T) {
	f := newManagedLogoutFixture(t)

	checkStatus(t, f.manage(t, f.b, newID("b-first")), StatusSuccess, "")
	checkStatus(t, f.manage(t, f.b, newID("b-alias")), StatusSuccess, "")

	// A logs out, and the identity provider tells B, with the identifier that B has most recently registered.
	r, _ := redirectLogoutRequest(t, f.a, func(request *LogoutRequest) {
		nameID := f.asserted(f.a)
		request.NameID = &nameID
	})

	location := sentLogoutRequest(t, serveSLO(f.test, r))
	assert.Assert(t, is.Equal(location.Host, "sp-b.example.com"))

	expected := f.asserted(f.b)
	expected.SPProvidedID = "b-alias"

	assert.Check(t, is.DeepEqual(propagatedNameID(t, location), expected))
	assert.Check(t, is.Equal(f.asserted(f.b).SPProvidedID, ""))

	t.Run("none registered", func(t *testing.T) {
		f := newManagedLogoutFixture(t)
		checkStatus(t, f.manage(t, f.b, newID("b-alias")), StatusSuccess, "")

		// The alias of B is not that of A, which is told with its identifier as it was asserted.
		f.only(f.a)

		location := sentLogoutRequest(t, f.startLogout(t))
		assert.Check(t, is.DeepEqual(propagatedNameID(t, location), f.asserted(f.a)))
	})

	t.Run("lookup fails", func(t *testing.T) {
		f := newManagedLogoutFixture(t)
		f.only(f.b)
		f.names.lookupErr = errors.New("directory unavailable")

		// The service provider is still told, with the identifier that was asserted to it.
		location := sentLogoutRequest(t, f.startLogout(t))
		assert.Check(t, is.DeepEqual(propagatedNameID(t, location), f.asserted(f.b)))
	})
}

// Errata E8: a Terminate does not end the sessions of the principal, so the service provider can still log out
// of the one it has, and is still told of a logout, with the identifier that the session was established with.
// Errata E12 and SAMLCore §8.3.7: the SPProvidedID that it had registered went with the identifier, so it is no
// longer part of it.
func TestTerminateNameIDKeepsSessions(t *testing.T) {
	terminated := func(t *testing.T) *managedLogoutFixture {
		t.Helper()

		f := newManagedLogoutFixture(t)

		checkStatus(t, f.manage(t, f.a, newID("a-alias")), StatusSuccess, "")
		checkStatus(t, f.manage(t, f.a, terminateNameID), StatusSuccess, "")

		assert.Check(t, is.Len(f.provider.terminated, 0))
		assert.Check(t, is.Len(f.provider.participants[f.session.ID], 2))
		assert.Check(t, is.Len(f.provider.closed, 0))

		return f
	}

	t.Run("logout with the identifier of the session", func(t *testing.T) {
		f := terminated(t)
		f.only(f.a)

		checkStatus(t, f.logout(t, f.a, f.asserted(f.a)), StatusSuccess, "")
		assert.Check(t, is.DeepEqual(f.provider.terminated, []*Session{f.session}))
	})

	t.Run("logout with the SPProvidedID that was terminated", func(t *testing.T) {
		f := terminated(t)
		f.only(f.a)

		nameID := f.asserted(f.a)
		nameID.SPProvidedID = "a-alias"

		f.logout(t, f.a, nameID)
		assert.Check(t, is.Len(f.provider.terminated, 0))
	})

	t.Run("propagated logout", func(t *testing.T) {
		f := terminated(t)
		f.only(f.a)

		location := sentLogoutRequest(t, f.startLogout(t))
		assert.Check(t, is.DeepEqual(propagatedNameID(t, location), f.asserted(f.a)))
	})
}

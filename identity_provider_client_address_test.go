package saml

import (
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// assertedAddresses returns the Address of the subject confirmation data and of the subject
// locality of the assertion made for session, from a request sent from remoteAddr.
func assertedAddresses(t *testing.T, remoteAddr string, session *Session) (string, string) {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	req, err := hardeningValidate(test, hardeningRequest(`ID="id-1"`, TimeNow(), hardeningIssuer))
	assert.NilError(t, err)
	req.HTTPRequest.RemoteAddr = remoteAddr
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, session))

	confirmations := req.Assertion.Subject.SubjectConfirmations
	assert.Assert(t, is.Len(confirmations, 1))
	assert.Assert(t, confirmations[0].SubjectConfirmationData != nil)
	assert.Assert(t, is.Len(req.Assertion.AuthnStatements, 1))
	assert.Assert(t, req.Assertion.AuthnStatements[0].SubjectLocality != nil)
	return confirmations[0].SubjectConfirmationData.Address, req.Assertion.AuthnStatements[0].SubjectLocality.Address
}

// SAMLCore §2.4.1.2 and §2.7.2.1 give the Address as an IP address, without a port.
func TestAssertionAddressIsClientIP(t *testing.T) {
	for name, tc := range map[string]struct {
		remoteAddr, sessionAddress, asserted string
	}{
		"ipv4":                 {remoteAddr: "192.0.2.1:1234", asserted: "192.0.2.1"},
		"ipv6":                 {remoteAddr: "[2001:db8::1]:1234", asserted: "2001:db8::1"},
		"ipv6 zone":            {remoteAddr: "[fe80::1%eth0]:1234", asserted: "fe80::1"},
		"no port":              {remoteAddr: "192.0.2.1", asserted: "192.0.2.1"},
		"not an address":       {remoteAddr: "@", asserted: ""},
		"empty":                {remoteAddr: "", asserted: ""},
		"from the session":     {remoteAddr: "198.51.100.7:1234", sessionAddress: "192.0.2.1", asserted: "192.0.2.1"},
		"invalid from session": {remoteAddr: "198.51.100.7:1234", sessionAddress: "192.0.2.1:1234", asserted: ""},
	} {
		t.Run(name, func(t *testing.T) {
			confirmation, locality := assertedAddresses(t, tc.remoteAddr, &Session{ID: "s", NameID: "alice", ClientAddress: tc.sessionAddress})
			assert.Check(t, is.Equal(confirmation, tc.asserted))
			assert.Check(t, is.Equal(locality, tc.asserted))
		})
	}
}

// A request which names the client IP in its subject confirmation can now be met.
func TestServeSSOMatchesConfirmationAddress(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w := serveSSOWithSubject(t, test, &Session{ID: "s", NameID: "alice"}, &Subject{
		NameID: &NameID{Value: "alice"},
		SubjectConfirmations: []SubjectConfirmation{{
			Method:                  bearerSubjectConfirmationMethod,
			SubjectConfirmationData: &SubjectConfirmationData{Address: "192.0.2.1"},
		}},
	})
	assert.Check(t, is.Equal(subjectResponse(t, w).Status.StatusCode.Value, StatusSuccess))
}

package saml

import (
	"net/http"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// setClockSkew sets MaxClockSkew for the test.
func setClockSkew(t *testing.T, skew time.Duration) {
	t.Helper()

	previous := MaxClockSkew

	t.Cleanup(func() { MaxClockSkew = previous })

	MaxClockSkew = skew
}

// SAML2Int SDP-G01: every time that another party states is valid from MaxClockSkew before its NotBefore,
// inclusive, to MaxClockSkew after its NotOnOrAfter, exclusive.
func TestClockSkewValidity(t *testing.T) {
	now := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)

	for name, skew := range map[string]time.Duration{"none": 0, "default": MaxClockSkew, "five minutes": 5 * time.Minute} {
		t.Run(name, func(t *testing.T) {
			setClockSkew(t, skew)

			// NotBefore: the clock of this party may be behind that of the party that stated it.
			assert.Check(t, !beforeValidity(now, now))
			assert.Check(t, !beforeValidity(now.Add(skew), now), "at the clock skew")
			assert.Check(t, beforeValidity(now.Add(skew+time.Millisecond), now), "beyond the clock skew")
			assert.Check(t, !beforeValidity(time.Time{}, now), "no NotBefore")

			// NotOnOrAfter: the clock of this party may be ahead.
			assert.Check(t, !pastValidity(now.Add(time.Millisecond), now))
			assert.Check(t, !pastValidity(now.Add(-skew+time.Millisecond), now), "within the clock skew")
			assert.Check(t, pastValidity(now.Add(-skew), now), "at the clock skew")
			assert.Check(t, pastValidity(time.Time{}, now), "the zero time is in the past")

			// validUntil is a NotOnOrAfter that may be absent.
			assert.Check(t, !expiredAt(now.Add(-skew+time.Millisecond), now), "within the clock skew")
			assert.Check(t, expiredAt(now.Add(-skew), now), "at the clock skew")
			assert.Check(t, !expiredAt(time.Time{}, now), "no validUntil")

			// A validUntil that is too far ahead: the clock of the publisher may be ahead.
			assert.Check(t, !validBeyond(now.Add(time.Hour), now, time.Hour))
			assert.Check(t, !validBeyond(now.Add(time.Hour+skew), now, time.Hour), "at the clock skew")
			assert.Check(t, validBeyond(now.Add(time.Hour+skew+time.Millisecond), now, time.Hour), "beyond the clock skew")
		})
	}
}

// issueInstantBounds are the offsets of an IssueInstant from now at each end of what is accepted, for a maximum
// age of MaxIssueDelay: just inside and just outside, on both sides.
var issueInstantBounds = []struct {
	name     string
	offset   func() time.Duration
	accepted bool
	err      string
}{
	{name: "now", offset: func() time.Duration { return 0 }, accepted: true},
	{name: "within the maximum age", offset: func() time.Duration { return -MaxIssueDelay + time.Second }, accepted: true},
	{name: "older, within the clock skew", offset: func() time.Duration { return -MaxIssueDelay - MaxClockSkew + time.Second }, accepted: true},
	{name: "older by the clock skew", offset: func() time.Duration { return -MaxIssueDelay - MaxClockSkew }, err: "expired at"},
	{name: "in the future, at the clock skew", offset: func() time.Duration { return MaxClockSkew }, accepted: true},
	{name: "in the future, beyond the clock skew", offset: func() time.Duration { return MaxClockSkew + time.Second }, err: "issued in the future at"},
}

func TestCheckIssueInstant(t *testing.T) {
	now := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)

	for name, skew := range map[string]time.Duration{"none": 0, "default": MaxClockSkew, "five minutes": 5 * time.Minute} {
		t.Run(name, func(t *testing.T) {
			setClockSkew(t, skew)

			for _, tc := range issueInstantBounds {
				err := checkIssueInstant("request", now.Add(tc.offset()), now, MaxIssueDelay)
				if tc.accepted {
					assert.Check(t, err, tc.name)
					continue
				}

				assert.Check(t, is.ErrorContains(err, "request "+tc.err), tc.name)
			}

			// The time in the error is the one that the message stated, without the clock skew.
			err := checkIssueInstant("response", now.Add(-time.Hour), now, MaxIssueDelay)
			assert.Check(t, is.Error(err, "response expired at "+now.Add(-time.Hour+MaxIssueDelay).String()))
		})
	}
}

// Every message that the identity provider receives has its IssueInstant checked in the same way: a service
// provider whose clock is behind or ahead by less than MaxClockSkew is not refused (SAML2Int SDP-G01).
func TestIDPAllowsClockSkewOnIssueInstant(t *testing.T) {
	status := func(s Status) bool { return s.StatusCode.Value == StatusSuccess }

	sites := map[string]func(t *testing.T, issueInstant time.Time) bool{
		"AuthnRequest": func(t *testing.T, issueInstant time.Time) bool {
			_, err := hardeningValidate(NewIdentityProviderTest(t, applyKey), hardeningRequest(`ID="id-1"`, issueInstant, hardeningIssuer))

			return err == nil
		},
		"AuthnRequest over ECP": func(t *testing.T, issueInstant time.Time) bool {
			test, _ := ecpTestIDP(t, nil)
			w, _ := serveECP(t, test, func(r *AuthnRequest) { r.IssueInstant = issueInstant })

			return status(parseECPResponse(t, w).Response.Status)
		},
		"LogoutRequest": func(t *testing.T, issueInstant time.Time) bool {
			test, _ := logoutTestIDP(t)
			r, _ := redirectLogoutRequest(t, &test.SP, func(r *LogoutRequest) { r.IssueInstant = issueInstant })
			_, response := redirectedLogoutResponse(t, serveSLO(test, r))

			return status(response.Status)
		},
		"LogoutRequest over SOAP": func(t *testing.T, issueInstant time.Time) bool {
			test, _ := soapLogoutTestIDP(t)
			r, _ := soapLogoutRequest(t, &test.SP, func(r *LogoutRequest) { r.IssueInstant = issueInstant })

			return status(soapLogoutResponse(t, serveSOAPLogout(test, r)).Status)
		},
		"LogoutResponse": func(t *testing.T, issueInstant time.Time) bool {
			test, _ := logoutTestIDP(t)
			r := signedLogoutResponse(t, HTTPPostBinding, &test.SP, &test.SP, func(r *LogoutResponse) { r.IssueInstant = issueInstant })
			_, err := validateLogoutResponse(test, r, logoutResponseState(test))

			return err == nil
		},
		"ArtifactResolve": func(t *testing.T, issueInstant time.Time) bool {
			test, _ := artifactTestIDP(t)
			artifact, _ := issueTestArtifact(t, test, &test.SP)
			r, _ := artifactResolvePost(t, &test.SP, artifact, func(r *ArtifactResolve) { r.IssueInstant = issueInstant })
			_, message := artifactResponse(t, serveArtifactResolution(test, r))

			return message != nil
		},
		"ManageNameIDRequest": func(t *testing.T, issueInstant time.Time) bool {
			test, _ := manageNameIDTestIDP(t)
			result := manageNameIDBindings["soap"](t, test, manageNameIDOptions{mutate: func(r *ManageNameIDRequest) { r.IssueInstant = issueInstant }})
			assert.Assert(t, result.Response != nil, "HTTP status %d", result.Code)

			return status(result.Response.Status)
		},
		"ManageNameIDResponse": func(t *testing.T, issueInstant time.Time) bool {
			test, sp, _ := sendManageNameIDFixture(t)
			sp.respond = func(_ http.ResponseWriter, response *ManageNameIDResponse) bool {
				response.IssueInstant = issueInstant

				return true
			}

			return sendManageNameID(test, NameIDChange{NameID: *testNameID(test, &test.SP), Terminate: true}) == nil
		},
		"NameIDMappingRequest": func(t *testing.T, issueInstant time.Time) bool {
			result := newNameIDMappingFixture(t).send(t, nameIDMappingOptions{mutate: func(r *NameIDMappingRequest) { r.IssueInstant = issueInstant }})

			return status(result.Response.Status)
		},
	}

	for _, service := range queryServices {
		sites[service.name] = func(t *testing.T, issueInstant time.Time) bool {
			f := newQueryFixture(t)
			message := service.message(f)
			message.CreateAttr("IssueInstant", issueInstant.Format(timeFormat))

			return status(f.query(t, service, message).Response.Status)
		}
	}

	for name, accepted := range sites {
		for _, tc := range issueInstantBounds {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				// The fixture sets the clock, which the offset is from.
				NewIdentityProviderTest(t, applyKey)

				assert.Check(t, is.Equal(accepted(t, TimeNow().Add(tc.offset())), tc.accepted))
			})
		}
	}
}

// What the identity provider records of a request outlives every instant at which an instance of it accepts the
// request: MaxClockSkew after it is too old, and MaxClockSkew longer for an instance whose clock is behind.
func TestIDPRecordsRequestForTheClockSkewOfAcceptance(t *testing.T) {
	test, _ := soapLogoutTestIDP(t)
	store := newRecordingReplayStore()
	test.IDP.ReplayStore = store

	issued := TimeNow().Add(-MaxIssueDelay - MaxClockSkew + time.Second)

	r, _ := soapLogoutRequest(t, &test.SP, func(r *LogoutRequest) { r.IssueInstant = issued })
	assertLogoutStatus(t, soapLogoutResponse(t, serveSOAPLogout(test, r)), StatusSuccess, "")

	assert.Assert(t, is.Equal(store.calls(), 1))
	assert.Check(t, store.expiries[0].Equal(issued.Add(MaxIssueDelay+2*MaxClockSkew)))
	assert.Check(t, store.expiries[0].After(TimeNow().Add(MaxClockSkew)))
}

// clockSkewAssertion returns a service provider and an assertion that it accepts at now.
func clockSkewAssertion(now time.Time) (*ServiceProvider, *Assertion) {
	sp := &ServiceProvider{
		EntityID:    "https://sp.example.com/metadata",
		AcsURL:      mustParseURL("https://sp.example.com/acs"),
		IDPMetadata: &EntityDescriptor{EntityID: "https://idp.example.com/metadata"},
	}

	return sp, &Assertion{
		ID:           "id-assertion",
		IssueInstant: now,
		Issuer:       Issuer{Value: sp.IDPMetadata.EntityID},
		Subject: &Subject{SubjectConfirmations: []SubjectConfirmation{{
			Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
			SubjectConfirmationData: &SubjectConfirmationData{
				InResponseTo: "id-request",
				Recipient:    sp.AcsURL.String(),
				NotOnOrAfter: now.Add(time.Hour),
			},
		}}},
		Conditions: &Conditions{
			NotBefore:            now.Add(-time.Hour),
			NotOnOrAfter:         now.Add(time.Hour),
			AudienceRestrictions: []AudienceRestriction{{Audiences: []Audience{{Value: sp.EntityID}}}},
		},
	}
}

// The service provider allows clock skew in the same way on each time of an assertion: its IssueInstant, the
// NotBefore and the NotOnOrAfter of its Conditions, and the NotOnOrAfter of its bearer confirmation.
func TestSPAllowsClockSkewOnAssertion(t *testing.T) {
	now := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)

	for name, tc := range map[string]struct {
		mutate func(*Assertion)
		err    string
	}{
		"valid": {mutate: func(*Assertion) {}},
		"IssueInstant older, within the clock skew": {
			mutate: func(a *Assertion) { a.IssueInstant = now.Add(-MaxIssueDelay - MaxClockSkew + time.Second) },
		},
		"IssueInstant older by the clock skew": {
			mutate: func(a *Assertion) { a.IssueInstant = now.Add(-MaxIssueDelay - MaxClockSkew) },
			err:    "assertion expired at",
		},
		"IssueInstant in the future, at the clock skew": {
			mutate: func(a *Assertion) { a.IssueInstant = now.Add(MaxClockSkew) },
		},
		"IssueInstant in the future, beyond the clock skew": {
			mutate: func(a *Assertion) { a.IssueInstant = now.Add(MaxClockSkew + time.Second) },
			err:    "assertion issued in the future at",
		},
		"NotBefore at the clock skew": {
			mutate: func(a *Assertion) { a.Conditions.NotBefore = now.Add(MaxClockSkew) },
		},
		"NotBefore beyond the clock skew": {
			mutate: func(a *Assertion) { a.Conditions.NotBefore = now.Add(MaxClockSkew + time.Second) },
			err:    "assertion Conditions is not yet valid",
		},
		"Conditions NotOnOrAfter within the clock skew": {
			mutate: func(a *Assertion) { a.Conditions.NotOnOrAfter = now.Add(-MaxClockSkew + time.Second) },
		},
		"Conditions NotOnOrAfter the clock skew ago": {
			mutate: func(a *Assertion) { a.Conditions.NotOnOrAfter = now.Add(-MaxClockSkew) },
			err:    "assertion Conditions is expired",
		},
		"SubjectConfirmationData NotOnOrAfter within the clock skew": {
			mutate: func(a *Assertion) {
				a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = now.Add(-MaxClockSkew + time.Second)
			},
		},
		"SubjectConfirmationData NotOnOrAfter the clock skew ago": {
			mutate: func(a *Assertion) {
				a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = now.Add(-MaxClockSkew)
			},
			err: "assertion SubjectConfirmationData is expired",
		},
	} {
		t.Run(name, func(t *testing.T) {
			sp, assertion := clockSkewAssertion(now)
			tc.mutate(assertion)

			err := sp.validateAssertion(assertion, []string{"id-request"}, now)
			if tc.err == "" {
				assert.Check(t, err)
				return
			}

			assert.Check(t, is.ErrorContains(err, tc.err))
		})
	}
}

// The clock of the service provider is moved against a Response that the identity provider signed, so the
// IssueInstant of the Response is what refuses it at each end.
func TestSPAllowsClockSkewOnResponse(t *testing.T) {
	for _, tc := range issueInstantBounds {
		t.Run(tc.name, func(t *testing.T) {
			test, body := signedResponseForSP(t)

			// The IssueInstant is offset from now when now is that much the other way from the IssueInstant.
			now := TimeNow().Add(-tc.offset())
			TimeNow = func() time.Time { return now }

			_, err := test.SP.ParseXMLResponse([]byte(body), []string{"id-request"}, test.SP.AcsURL)
			if tc.accepted {
				assert.Check(t, err)
				return
			}

			assert.Check(t, is.ErrorContains(privateError(err), "response "+tc.err))
		})
	}
}

func TestSPAllowsClockSkewOnLogoutResponse(t *testing.T) {
	for _, tc := range issueInstantBounds {
		t.Run(tc.name, func(t *testing.T) {
			f := newLogoutResponseFixture(t)

			issued := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)
			TimeNow = func() time.Time { return issued }

			form := signedLogoutResponseForm(t, f, "id-request")

			TimeNow = func() time.Time { return issued.Add(-tc.offset()) }

			err := f.sp.ValidateLogoutResponseForm(form, []string{"id-request"})
			if tc.accepted {
				assert.Check(t, err)
				return
			}

			assert.Check(t, is.ErrorContains(privateError(err), "response "+tc.err))
		})
	}
}

// An artifact response is checked as a response is.
func TestSPAllowsClockSkewOnArtifactResponse(t *testing.T) {
	now := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)

	for _, tc := range issueInstantBounds {
		t.Run(tc.name, func(t *testing.T) {
			sp, _ := clockSkewAssertion(now)

			doc := etree.NewDocument()
			assert.NilError(t, doc.ReadFromString(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-response" InResponseTo="id-resolve" Version="2.0" IssueInstant="`+
				now.Add(tc.offset()).Format(timeFormat)+`"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://other.example.com</saml:Issuer></samlp:ArtifactResponse></soapenv:Body></soapenv:Envelope>`))

			TimeNow = func() time.Time { return now }

			_, err := sp.ParseXMLArtifactResponse(mustWriteDocument(t, doc), []string{"id-request"}, "id-resolve", sp.AcsURL)

			// The IssueInstant is checked before the Issuer, which is not that of the identity provider here.
			if tc.accepted {
				assert.Check(t, is.ErrorContains(privateError(err), "response Issuer does not match"))
				return
			}

			assert.Check(t, is.ErrorContains(privateError(err), "response "+tc.err))
		})
	}
}

func mustWriteDocument(t *testing.T, doc *etree.Document) []byte {
	t.Helper()

	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	return buf
}

// A descriptor of an affiliation, of a role and of an entity are current until MaxClockSkew after their validUntil.
func TestMetadataValidUntilAllowsClockSkew(t *testing.T) {
	now := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)
	within, ago := now.Add(-MaxClockSkew+time.Second), now.Add(-MaxClockSkew)

	metadata := func(entity time.Time, role *time.Time) *EntityDescriptor {
		descriptor := SPSSODescriptor{AssertionConsumerServices: []IndexedEndpoint{{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs", Index: 1}}}
		descriptor.ValidUntil = role

		return &EntityDescriptor{EntityID: "https://sp.example.com/metadata", ValidUntil: entity, SPSSODescriptors: []SPSSODescriptor{descriptor}}
	}

	assert.Check(t, CurrentMetadata(metadata(within, nil), now) != nil)
	assert.Check(t, CurrentMetadata(metadata(ago, nil), now) == nil)
	assert.Check(t, CurrentMetadata(metadata(time.Time{}, &within), now) != nil)
	assert.Check(t, CurrentMetadata(metadata(time.Time{}, &ago), now) == nil)

	idp := &IdentityProvider{}
	assert.Check(t, idp.CheckServiceProviderMetadata(metadata(within, nil), now))
	assert.Check(t, is.ErrorContains(idp.CheckServiceProviderMetadata(metadata(ago, nil), now), "expired"))
}

package saml

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/beevik/etree"

	"authelia.com/provider/saml/internal/dsig"
)

// IdpLogoutRequestForm is the data of LogoutRequestFormTemplate.
type IdpLogoutRequestForm struct {
	URL         string
	SAMLRequest string
	RelayState  string
}

var (
	// frontChannelLogoutBindings are the bindings a LogoutRequest is sent on while the browser is at the identity
	// provider, in order of preference. A request on the SOAP binding is still sent without the browser.
	frontChannelLogoutBindings = []string{HTTPRedirectBinding, HTTPPostBinding, SOAPBinding}

	// backChannelLogoutBindings are the bindings a LogoutRequest is sent on without the browser.
	backChannelLogoutBindings = []string{SOAPBinding}
)

// logoutRequestEndpoint returns the SingleLogoutService to send a LogoutRequest to: the first of the bindings, in
// order of preference, whose Location passes CheckServiceProviderEndpoint, or CheckServiceProviderBackChannelEndpoint
// on the SOAP binding.
func (idp *IdentityProvider) logoutRequestEndpoint(metadata *EntityDescriptor, bindings ...string) (*Endpoint, error) {
	var lastErr error

	for _, binding := range bindings {
		for i := range metadata.SPSSODescriptors {
			endpoints := metadata.SPSSODescriptors[i].SingleLogoutServices

			for j := range endpoints {
				if endpoints[j].Binding != binding {
					continue
				}

				if err := idp.checkServiceProviderBindingEndpoint(binding, endpoints[j].Location); err != nil {
					lastErr = err

					continue
				}

				return &endpoints[j], nil
			}
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errors.New("the service provider has no single logout service with a supported binding")
}

// makeLogoutRequest returns the unsigned LogoutRequest for p, whose metadata is given. A participant that was
// asserted its NameID as an EncryptedID is identified with an EncryptedID again (SAMLCore §3.7.1), encrypted to
// its encryption key before the request is signed (SAMLCore §6.2). If that fails an error is returned, rather than
// a request which shows the NameID.
//
// The NameID is the one that was asserted to the participant, with the SPProvidedID that it has registered
// since with a ManageNameIDRequest, if any, which SAMLCore §3.6.3 requires the identity provider to include from
// then on (see NameIDManagementProvider.SPProvidedID). If that can't be found, the failure is reported as an
// EventStore and the NameID is sent as it was asserted, rather than the participant being left logged in.
func (idp *IdentityProvider) makeLogoutRequest(r *http.Request, state *LogoutState, p *LogoutParticipant, metadata *EntityDescriptor, endpoint *Endpoint) (*LogoutRequest, error) {
	nameID := p.NameID

	switch alias, err := idp.spProvidedID(r, p.ServiceProviderEntityID, &nameID); {
	case err != nil:
		idp.observe(r, requestState{serviceProvider: p.ServiceProviderEntityID, verified: true, requestID: state.ID}.
			warning(EventStore, ErrServerError.WithDebugf("cannot find the SPProvidedID of the NameID: %s", err).WithWrap(err)))
	case alias != "":
		nameID.SPProvidedID = alias
	}

	request := &LogoutRequest{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		NotOnOrAfter: &state.ExpireTime,
		Destination:  endpoint.Location,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  idp.entityID(),
		},
		NameID: &nameID,
	}

	for _, index := range p.SessionIndexes {
		request.SessionIndexes = append(request.SessionIndexes, SessionIndex{Value: index})
	}

	if !p.NameIDEncrypted {
		return request, nil
	}

	encrypter, err := idp.serviceProviderElementEncrypter(metadata)
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt the NameID of the logout request: %w", err)
	}

	if request.EncryptedID, err = encrypter.encryptNameID(&nameID); err != nil {
		return nil, fmt.Errorf("cannot encrypt the NameID of the logout request: %w", err)
	}

	request.NameID = nil

	return request, nil
}

// continueLogout sends the browser to the next pending participant. A participant reached only on the SOAP binding
// is logged out during this request instead, without saving state. It saves state before writing. When no
// participant is pending it calls finishLogout. If the LogoutRequest to the next participant can't be signed or
// rendered, or the state can't be saved, that participant and every other pending one are marked Failed with the
// error as Reason, and the logout is finished at once, so that the origin is still answered. It returns an error only
// if nothing has been written to w: when the state was changed by another request, which wraps ErrLogoutStateConflict,
// or when finishLogout fails.
func (idp *IdentityProvider) continueLogout(w http.ResponseWriter, r *http.Request, provider LogoutStateProvider, state *LogoutState) error {
	for {
		current := -1

		for i := range state.Participants {
			if state.Participants[i].Outcome == LogoutOutcomePending {
				current = i

				break
			}
		}

		if current < 0 {
			return idp.finishLogout(w, r, provider, state)
		}

		participant := &state.Participants[current]

		metadata, err := idp.serviceProvider(r, participant.ServiceProviderEntityID)
		if err != nil {
			idp.skipLogoutParticipant(r, state, participant, err)

			continue
		}

		endpoint, err := idp.logoutRequestEndpoint(metadata, frontChannelLogoutBindings...)
		if err != nil {
			idp.skipLogoutParticipant(r, state, participant, err)

			continue
		}

		if endpoint.Binding == SOAPBinding {
			idp.sendSOAPLogoutRequest(r, state, current, metadata, endpoint)

			continue
		}

		request, err := idp.makeLogoutRequest(r, state, participant, metadata, endpoint)
		if err != nil {
			idp.skipLogoutParticipant(r, state, participant, err)

			continue
		}

		write, err := idp.prepareLogoutRequest(w, r, state, request, metadata, endpoint)
		if err != nil {
			idp.abandonLogout(r, state, fmt.Errorf("cannot make the logout request: %w", err))

			continue
		}

		state.Current = current
		state.PendingRequestID = request.ID

		if err = saveLogoutState(r, provider, state); errors.Is(err, ErrLogoutStateConflict) {
			return err
		} else if err != nil {
			idp.abandonLogout(r, state, fmt.Errorf("cannot save the logout state: %w", err))

			continue
		}

		return write()
	}
}

// saveLogoutState saves the next revision of state. On failure state keeps its revision.
func saveLogoutState(r *http.Request, provider LogoutStateProvider, state *LogoutState) error {
	state.Revision++

	if err := provider.SaveLogoutState(r, state); err != nil {
		state.Revision--

		return err
	}

	return nil
}

// writeContinueLogoutError writes the error of continueLogout, which has written nothing to w, and reports it as
// the failure of the logout of state: StatusConflict if the state was changed by another request, and otherwise
// StatusInternalServerError.
func (idp *IdentityProvider) writeContinueLogoutError(w http.ResponseWriter, r *http.Request, state *LogoutState, err error) {
	e := ErrServerError.WithDebugf("failed to continue logout: %s", err).WithWrap(err)

	if errors.Is(err, ErrLogoutStateConflict) {
		e = e.WithHTTPStatus(http.StatusConflict)
	}

	idp.observe(r, state.requestState().event(EventLogout, e))
	idp.writeHTTPError(w, r, e)
}

// abandonLogout marks every pending participant of state Failed with err as Reason, and clears the outstanding
// request, so that the logout finishes without sending another LogoutRequest. Each of them is reported as an
// EventLogoutPropagation that failed.
func (idp *IdentityProvider) abandonLogout(r *http.Request, state *LogoutState, err error) {
	for i := range state.Participants {
		if participant := &state.Participants[i]; participant.Outcome == LogoutOutcomePending {
			participant.Outcome, participant.Reason = LogoutOutcomeFailed, err.Error()

			idp.observeLogoutParticipant(r, state, participant, true,
				ErrServerError.WithDebugf("abandoning the logout: %s", err).WithWrap(err))
		}
	}

	state.Current, state.PendingRequestID = -1, ""
}

// skipLogoutParticipant marks participant Skipped with err as Reason, which is reported as an
// EventLogoutPropagation with a warning: the participant was sent nothing, and may still be logged in.
func (idp *IdentityProvider) skipLogoutParticipant(r *http.Request, state *LogoutState, participant *LogoutParticipant, err error) {
	participant.Outcome = LogoutOutcomeSkipped
	participant.Reason = err.Error()

	event := state.requestState().warning(EventLogoutPropagation,
		ErrServerError.WithDebugf("the session participant was not sent a logout request: %s", err).WithWrap(err))
	event.ServiceProvider, event.Verified = participant.ServiceProviderEntityID, true

	idp.observe(r, event)
}

// observeLogoutParticipant reports the logout of participant, which is done with, as an EventLogoutPropagation: a
// success if err is nil, a warning if err is the PartialLogout of a verified response, which is a success with a
// second-level status, and otherwise a failure. Whether the participant is verified is whether its response was.
// The participant keeps its outcome, so a partial logout still makes the logout as a whole partial.
func (idp *IdentityProvider) observeLogoutParticipant(r *http.Request, state *LogoutState, participant *LogoutParticipant, verified bool, err *StatusError) {
	event := Event{
		Kind:            EventLogoutPropagation,
		Outcome:         OutcomeSuccess,
		ServiceProvider: participant.ServiceProviderEntityID,
		Verified:        verified,
		RequestID:       state.ID,
	}

	switch {
	case err == nil:
	case verified && err.TopLevelField == StatusSuccess && err.SecondLevelField == StatusPartialLogout:
		event.Outcome, event.Err = OutcomeWarning, err
	default:
		event.Outcome, event.Err = OutcomeFailure, err
	}

	idp.observe(r, event)
}

// requestState returns the state for the events of the logout: the service provider that asked for it and the ID
// of its LogoutRequest, or the ID of the logout if the identity provider started it.
func (s *LogoutState) requestState() requestState {
	if s.Origin != nil {
		return requestState{serviceProvider: s.Origin.ServiceProviderEntityID, verified: true, requestID: s.Origin.RequestID, respondable: true}
	}

	return requestState{requestID: s.ID}
}

// prepareLogoutRequest signs the request, with the algorithms that the IssuancePolicy gives for the service
// provider with that metadata, and returns the function which writes it to w, so that nothing is written
// before the state is saved.
func (idp *IdentityProvider) prepareLogoutRequest(w http.ResponseWriter, r *http.Request, state *LogoutState, request *LogoutRequest, metadata *EntityDescriptor, endpoint *Endpoint) (func() error, error) {
	signingContext, err := idp.signingContextFor(r, metadata)
	if err != nil {
		return nil, err
	}

	switch endpoint.Binding {
	case HTTPRedirectBinding:
		u, err := redirectURLWithContext(endpoint.Location, "SAMLRequest", request.Element(), state.ID, signingContext)
		if err != nil {
			return nil, err
		}

		return func() error {
			setNoCacheHeaders(w)
			http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // G710: the location is from the service provider metadata, not the request.

			return nil
		}, nil
	case HTTPPostBinding:
		el, err := signLogoutRequestEnveloped(signingContext, request)
		if err != nil {
			return nil, err
		}

		doc := etree.NewDocument()
		doc.SetRoot(el)

		buf, err := doc.WriteToBytes()
		if err != nil {
			return nil, err
		}

		tmpl := idp.LogoutRequestFormTemplate
		if tmpl == nil {
			tmpl = defaultLogoutRequestFormTemplate
		}

		var body bytes.Buffer
		if err = tmpl.Execute(&body, IdpLogoutRequestForm{
			URL:         endpoint.Location,
			SAMLRequest: base64.StdEncoding.EncodeToString(buf),
			RelayState:  state.ID,
		}); err != nil {
			return nil, err
		}

		return func() error {
			setNoCacheHeaders(w)

			_, err := w.Write(body.Bytes())

			return err
		}, nil
	default:
		return nil, fmt.Errorf("unsupported binding %s", endpoint.Binding)
	}
}

// signLogoutRequestEnveloped signs request with an enveloped signature and returns its element, for a binding which
// carries the signature in the message.
func signLogoutRequestEnveloped(signingContext *dsig.SigningContext, request *LogoutRequest) (*etree.Element, error) {
	signedEl, err := signingContext.SignEnveloped(request.Element())
	if err != nil {
		return nil, err
	}

	// SAMLCore requires the signature to follow the Issuer, rather than come last.
	request.Signature = signedEl.ChildElements()[len(signedEl.ChildElements())-1]

	return request.Element(), nil
}

// ErrLogoutNotPropagated is wrapped by the error of StartLogout when the session at the identity provider was ended,
// but the logout could not begin, so no service provider was sent a LogoutRequest and each may still be logged in
// (SAMLProfiles §4.4). Nothing has been written to the response but headers, so the caller completes it.
var ErrLogoutNotPropagated = errors.New("the session was ended but the logout was not propagated to the service providers")

// StartLogout logs the user of session out of the identity provider and of every service provider it signed into,
// and finishes with LogoutResultHandler or a redirect to returnURL, which is not validated. The SessionProvider must
// implement LogoutSessionProvider, SessionParticipantProvider and LogoutStateProvider.
//
// This is the front-channel IdP-initiated logout of SAMLProfiles §4.4: each service provider is sent a LogoutRequest
// in turn through the browser, and answers at IdentityProvider.LogoutURL, which ServeSLO handles. A service provider
// whose only single logout service is on the SOAP binding is instead logged out over SOAP during the same request,
// without the browser. The caller must protect whatever triggers StartLogout against cross-site request forgery,
// such as by accepting only a same-origin POST, as it ends the session and sends the browser away.
//
// It returns nil once it has written to w, including when a later step fails. Otherwise it writes no status or body,
// and returns an error:
//   - When session is nil, the SessionProvider lacks one of the interfaces, or returnURL is empty and the
//     SessionProvider doesn't implement LogoutResultHandler, it ends nothing.
//   - When the participants of the session can't be read or the state can't be saved, it still ends the session with
//     TerminateSession, which may set headers, as ServeSLO does, and returns an error wrapping ErrLogoutNotPropagated.
//   - When the session also can't be ended, the error doesn't wrap ErrLogoutNotPropagated, and the session at the
//     identity provider may still be alive.
func (idp *IdentityProvider) StartLogout(w http.ResponseWriter, r *http.Request, session *Session, returnURL string) error {
	if session == nil {
		return errors.New("cannot start a logout without a session")
	}

	sessionProvider, _, _, err := idp.logoutProviders()
	if err != nil {
		return err
	}

	if _, ok := idp.SessionProvider.(LogoutResultHandler); !ok && returnURL == "" {
		return errors.New("cannot start a logout without a return URL when the session provider does not implement LogoutResultHandler")
	}

	if err = idp.beginLogout(w, r, []*Session{session}, "", returnURL, nil); err == nil {
		return nil
	}

	if termErr := sessionProvider.TerminateSession(w, r, session); termErr != nil && !errors.Is(termErr, ErrPartialLogout) {
		return fmt.Errorf("cannot end the session after the logout could not begin: %w", errors.Join(err, termErr))
	}

	return fmt.Errorf("%w: %w", ErrLogoutNotPropagated, err)
}

// logoutProviders returns the SessionProvider as each interface that a propagated logout needs, or an error naming
// the first it lacks.
func (idp *IdentityProvider) logoutProviders() (LogoutSessionProvider, SessionParticipantProvider, LogoutStateProvider, error) {
	sessions, ok := idp.SessionProvider.(LogoutSessionProvider)
	if !ok {
		return nil, nil, nil, errors.New("the session provider does not implement LogoutSessionProvider")
	}

	participants, ok := idp.SessionProvider.(SessionParticipantProvider)
	if !ok {
		return nil, nil, nil, errors.New("the session provider does not implement SessionParticipantProvider")
	}

	states, ok := idp.SessionProvider.(LogoutStateProvider)
	if !ok {
		return nil, nil, nil, errors.New("the session provider does not implement LogoutStateProvider")
	}

	return sessions, participants, states, nil
}

// beginLogout closes and reads the participants of the sessions, so that no service provider is sent an assertion for
// them that this logout won't reach, leaving out the service provider with excludeEntityID, saves
// the state with the returnURL or origin that the logout finishes with, ends the sessions and sends the browser to
// the first participant. The sessions are ended before any participant is visited, so a service provider that never
// returns the browser can't leave the user logged in at the identity provider (SAMLProfiles §4.4.3.2 leaves the
// timing to the identity provider).
//
// It returns an error, having written nothing, if it fails before the sessions are ended. After that a failure to
// reach a participant finishes the logout with that participant failed, and only a failure in finishLogout is
// written to w as an HTTP error.
func (idp *IdentityProvider) beginLogout(w http.ResponseWriter, r *http.Request, sessions []*Session, excludeEntityID, returnURL string, origin *LogoutOrigin) error {
	sessionProvider, participantProvider, stateProvider, err := idp.logoutProviders()
	if err != nil {
		return err
	}

	participants, err := closeSessionParticipants(r, participantProvider, sessions)
	if err != nil {
		return err
	}

	state := newLogoutState(idp, participants, excludeEntityID)
	state.ReturnURL, state.Origin = returnURL, origin

	if err = saveLogoutState(r, stateProvider, state); err != nil {
		return fmt.Errorf("cannot save the logout state: %w", err)
	}

	idp.terminateLogoutSessions(w, r, sessionProvider, sessions, state, state.requestState())

	// continueLogout saves the state again, with the result of the termination, before it writes.
	if err = idp.continueLogout(w, r, stateProvider, state); err != nil {
		idp.writeContinueLogoutError(w, r, state, err)
	}

	return nil
}

// closeSessionParticipants closes the participants of every one of the sessions and returns them, so that no service
// provider is sent an assertion for them that the logout won't reach.
func closeSessionParticipants(r *http.Request, provider SessionParticipantProvider, sessions []*Session) ([]SessionParticipant, error) {
	var participants []SessionParticipant

	for _, session := range sessions {
		found, err := provider.CloseSessionParticipants(r, session)
		if err != nil {
			return nil, fmt.Errorf("cannot find the service providers of the session: %w", err)
		}

		participants = append(participants, found...)
	}

	return participants, nil
}

// terminateLogoutSessions ends the sessions and records SessionTerminated and PartialLogout on state, for beginLogout
// and soapLogoutStatus. A failure to end a session doesn't stop the logout: the service providers are still logged
// out, and the result reports that the session was not ended. It is reported as an EventSessionTermination for the
// request in requestState.
func (idp *IdentityProvider) terminateLogoutSessions(w http.ResponseWriter, r *http.Request, provider LogoutSessionProvider, sessions []*Session, state *LogoutState, requestState requestState) {
	state.SessionTerminated = true

	for _, session := range sessions {
		err := provider.TerminateSession(w, r, session)

		switch {
		case err == nil:
		case errors.Is(err, ErrPartialLogout):
			state.PartialLogout = true
		default:
			idp.observe(r, requestState.warning(EventSessionTermination, ErrServerError.WithDebugf("cannot terminate session: %s", err).WithWrap(err)))

			state.SessionTerminated = false
		}
	}
}

// finishLogout deletes the state and ends the logout. A service provider that started it is sent its LogoutResponse;
// otherwise the LogoutResultHandler is called, or the browser is redirected to the return URL. It returns an error
// only if nothing has been written to w, which wraps ErrLogoutStateConflict if another request changed the state.
//
// The state is first saved with no outstanding request, so that of two requests which loaded the same revision only
// one finishes the logout, and a stale copy can't save it again once it is deleted. It is deleted only if that save
// succeeds: when the save fails for another reason the logout is still finished, so the browser isn't stranded, but
// the stored state is left to expire, as it may be a newer revision which another request saved.
//
// This is where a propagated logout is reported to the Observer as an EventLogout, with the outcome that
// IdpLogoutRequest.answer describes.
func (idp *IdentityProvider) finishLogout(w http.ResponseWriter, r *http.Request, provider LogoutStateProvider, state *LogoutState) error {
	state.Current, state.PendingRequestID = -1, ""

	switch err := saveLogoutState(r, provider, state); {
	case errors.Is(err, ErrLogoutStateConflict):
		return err
	case err != nil:
		idp.observe(r, state.requestState().warning(EventStore,
			ErrServerError.WithDebugf("failed to save logout state before finishing, leaving it to expire: %s", err).WithWrap(err)))
	default:
		if err = provider.DeleteLogoutState(r, state.ID); err != nil {
			idp.observe(r, state.requestState().warning(EventStore,
				ErrServerError.WithDebugf("failed to delete logout state: %s", err).WithWrap(err)))
		}
	}

	if origin := state.Origin; origin != nil {
		// The response is signed with the algorithms for the service provider that asked. If it is no longer
		// known it is still answered, at the endpoint that was checked when it asked, with those of the identity
		// provider.
		metadata, err := idp.serviceProvider(r, origin.ServiceProviderEntityID)
		if err != nil {
			metadata = nil
		}

		req := &IdpLogoutRequest{
			IDP:                     idp,
			HTTPRequest:             r,
			RelayState:              origin.RelayState,
			Request:                 LogoutRequest{ID: origin.RequestID},
			ServiceProviderMetadata: metadata,
			SLOEndpoint:             &origin.SLOEndpoint,
			Now:                     TimeNow(),
		}

		status := state.status()

		if err = req.WriteResponse(w, status); err != nil {
			return err
		}

		idp.observe(r, logoutStatusEvent(state.requestState(), status, nil))

		return nil
	}

	idp.observe(r, logoutStatusEvent(state.requestState(), state.status(), nil))

	if handler, ok := idp.SessionProvider.(LogoutResultHandler); ok {
		handler.FinishLogout(w, r, state.result())

		return nil
	}

	setNoCacheHeaders(w)
	// The return URL is chosen by the application, not the request. The gosec G710 finding here is excluded in
	// .golangci.yml rather than by a directive, as its taint analysis does not report it on every run.
	http.Redirect(w, r, state.ReturnURL, http.StatusFound)

	return nil
}

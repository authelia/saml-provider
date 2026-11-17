package saml

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/beevik/etree"
)

// samlProtocolNS is the namespace of the SAML protocol messages.
const samlProtocolNS = "urn:oasis:names:tc:SAML:2.0:protocol"

// defaultHTTPClientTimeout is the timeout of the client that httpClient returns when HTTPClient is not set.
const defaultHTTPClientTimeout = 10 * time.Second

// httpClient returns a client which follows no redirects: a copy of HTTPClient, with the 10 second timeout if its
// Timeout is 0, or a client with the 10 second timeout.
func (idp *IdentityProvider) httpClient() *http.Client {
	client := &http.Client{}

	if idp.HTTPClient != nil {
		*client = *idp.HTTPClient
	}

	if client.Timeout == 0 {
		client.Timeout = defaultHTTPClientTimeout
	}

	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return client
}

// sendSOAPLogoutRequest logs participant state.Participants[i] out over SOAP at endpoint and records its
// Outcome and Reason. It leaves state.Current at -1 and PendingRequestID empty. The exchange is not cancelled with
// r: the sessions are already ended and the participant records consumed, so a participant abandoned because the
// client went away could never be retried. HTTPClient's timeout still bounds it.
func (idp *IdentityProvider) sendSOAPLogoutRequest(r *http.Request, state *LogoutState, i int, endpoint *Endpoint) {
	r = r.WithContext(context.WithoutCancel(r.Context()))

	participant := &state.Participants[i]
	request := idp.makeLogoutRequest(state, participant, endpoint)

	state.Current, state.PendingRequestID = i, request.ID

	defer func() {
		state.Current, state.PendingRequestID = -1, ""
	}()

	if err := idp.exchangeSOAPLogoutRequest(r, state, request, endpoint); err != nil {
		idp.logger().Printf("failed to log %s out over SOAP: %s", participant.ServiceProviderEntityID, err)

		participant.Outcome, participant.Reason = LogoutOutcomeFailed, err.Error()
	}
}

// exchangeSOAPLogoutRequest signs request, posts it to endpoint in a SOAP envelope, validates the LogoutResponse
// that comes back against the outstanding request of state, and records its outcome.
func (idp *IdentityProvider) exchangeSOAPLogoutRequest(r *http.Request, state *LogoutState, request *LogoutRequest, endpoint *Endpoint) error {
	signingContext, err := idp.signingContext()
	if err != nil {
		return fmt.Errorf("cannot sign the logout request: %w", err)
	}

	el, err := signLogoutRequestEnveloped(signingContext, request)
	if err != nil {
		return fmt.Errorf("cannot sign the logout request: %w", err)
	}

	doc, envelope := newSOAPEnvelope()
	envelope.CreateElement("soapenv:Body").AddChild(el)

	buf, err := doc.WriteToBytes()
	if err != nil {
		return fmt.Errorf("cannot serialize the logout request: %w", err)
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint.Location, bytes.NewReader(buf)) //nolint:gosec // G704: the URL is from the service provider metadata and passed CheckServiceProviderBackChannelEndpoint.
	if err != nil {
		return fmt.Errorf("cannot make the logout request: %w", err)
	}

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	// SOAP 1.1 §6.1.1 makes the value a quoted string.
	req.Header.Set("SOAPAction", `"`+soapActionSAML+`"`)

	res, err := idp.httpClient().Do(req) //nolint:gosec // G704: as above.
	if err != nil {
		return fmt.Errorf("cannot send the logout request: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("the service provider answered with HTTP status %d", res.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, soapMaxMessageSize+1))
	if err != nil {
		return fmt.Errorf("cannot read the logout response: %w", err)
	}

	if len(body) > soapMaxMessageSize {
		return fmt.Errorf("the logout response is larger than %d bytes", soapMaxMessageSize)
	}

	message, err := soapResponseMessage(body)
	if err != nil {
		return err
	}

	resp := newSOAPLogoutResponse(idp, r, message, res.TLS != nil)

	if err = resp.Validate(state); err != nil {
		return fmt.Errorf("invalid logout response: %w", err)
	}

	resp.outcome(state)

	return nil
}

// soapResponseMessage returns the message in the SOAP envelope of a response, serialized standalone, or an error if
// the envelope is invalid or carries a Fault.
func soapResponseMessage(body []byte) ([]byte, error) {
	_, _, message, err := parseSOAPEnvelope(body)
	if err != nil {
		return nil, fmt.Errorf("invalid logout response envelope: %w", err)
	}

	if message.Tag == "Fault" && message.NamespaceURI() == soapEnvelopeNS {
		return nil, errors.New("the service provider answered with a SOAP fault")
	}

	doc := etree.NewDocument()
	doc.SetRoot(message)

	buf, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("cannot serialize the logout response: %w", err)
	}

	return buf, nil
}

// ServeSOAPLogout handles a SAML LogoutRequest from a service provider on the SOAP binding, at SOAPLogoutURL, and
// answers on the same connection with a signed LogoutResponse in a SOAP envelope. The request must carry an
// enveloped signature by its issuer, as SAMLProfiles §4.4.4.1 requires it to be authenticated. The session at the
// identity provider is ended by the SessionProvider, which must implement LogoutSessionProvider; headers that
// TerminateSession sets are discarded, as there is no browser to receive them.
//
// If the SessionProvider also implements SessionParticipantProvider, the session is ended and then every other
// participant of it is sent a LogoutRequest over SOAP in turn, before the requester is answered (SAMLProfiles
// §4.4.3.2). There is no browser to send to a participant on another binding, so it is skipped. The answer is
// Responder if the session was not ended, and otherwise Success, with a PartialLogout second-level status if any
// participant was skipped or not logged out, or if the participants could not be read.
//
// Every SAML message gets a LogoutResponse: one that is not a LogoutRequest gets Requester/RequestUnsupported, one
// that can't be verified gets Requester/RequestDenied, and one that is verified but expired, for another destination
// or of another version gets the matching error status, as does a replay of a request that was already verified,
// which is Requester/RequestDenied (SAMLSec §6.1.2). Its session is not ended. A request that is not a POST gets
// StatusMethodNotAllowed, one that is not a SOAP 1.1 envelope gets a Client fault, and a failure to sign or write
// the response gets a Server fault.
func (idp *IdentityProvider) ServeSOAPLogout(w http.ResponseWriter, r *http.Request) {
	soap, ok := idp.receiveSOAPRequest(w, r)
	if !ok {
		return
	}

	req := newSOAPLogoutRequest(idp, r, soap)

	var status Status

	if soap.Message.Tag != "LogoutRequest" || soap.Message.NamespaceURI() != samlProtocolNS {
		idp.logger().Printf("failed to handle SOAP logout request: the message is not a LogoutRequest")

		// MakeResponse answers it only if the ID is valid.
		req.Request.ID = soap.Message.SelectAttrValue("ID", "")
		status = Status{StatusCode: StatusCode{Value: StatusRequester, StatusCode: &StatusCode{Value: StatusRequestUnsupported}}}
	} else if err := req.Validate(); err != nil {
		idp.logger().Printf("failed to validate SOAP logout request: %s", err)

		if status, ok = RequestStatus(err); !ok {
			status = Status{StatusCode: StatusCode{Value: StatusRequester, StatusCode: &StatusCode{Value: StatusRequestDenied}}}
		}
	} else {
		status = idp.soapLogoutStatus(r, req)
	}

	if err := req.WriteResponse(w, status); err != nil {
		idp.logger().Printf("failed to write SOAP logout response: %s", err)
		writeSOAPFault(w, &soapFault{Code: "Server", String: soapFaultStringProcessing})
	}
}

// soapLogoutStatus ends the sessions that the verified req names, and returns the status of its LogoutResponse. If
// the SessionProvider implements SessionParticipantProvider, the other participants of the sessions are first logged
// out over SOAP; the state of that logout is never saved.
func (idp *IdentityProvider) soapLogoutStatus(r *http.Request, req *IdpLogoutRequest) Status {
	provider, ok := idp.SessionProvider.(LogoutSessionProvider)
	if !ok {
		idp.logger().Printf("cannot terminate session: the session provider does not implement LogoutSessionProvider")

		return Status{StatusCode: StatusCode{Value: StatusResponder}}
	}

	sessions, err := provider.GetLogoutSessions(r, req)
	if err != nil {
		idp.logger().Printf("cannot find sessions to terminate: %s", err)

		return Status{StatusCode: StatusCode{Value: StatusResponder}}
	}

	w := &discardResponseWriter{header: http.Header{}}

	participantProvider, ok := idp.SessionProvider.(SessionParticipantProvider)
	if !ok || len(sessions) == 0 {
		return idp.terminateSessions(w, r, provider, sessions)
	}

	participants, err := closeSessionParticipants(r, participantProvider, sessions)
	if err != nil {
		idp.logger().Printf("cannot begin logout: %s", err)

		// The sessions are still ended, but the other participants were not told, so a Success is partial.
		return withPartialLogout(idp.terminateSessions(w, r, provider, sessions))
	}

	state := newLogoutState(idp, participants, req.ServiceProviderMetadata.EntityID)

	idp.terminateLogoutSessions(w, r, provider, sessions, state)
	idp.backChannelLogout(r, state)

	return state.status()
}

// backChannelLogout logs every pending participant of state out over SOAP; one without a usable SOAP endpoint, or
// whose metadata can't be found, is Skipped. It is not cancelled with r, for the reason given at
// sendSOAPLogoutRequest.
func (idp *IdentityProvider) backChannelLogout(r *http.Request, state *LogoutState) {
	r = r.WithContext(context.WithoutCancel(r.Context()))

	for i := range state.Participants {
		participant := &state.Participants[i]

		if participant.Outcome != LogoutOutcomePending {
			continue
		}

		metadata, err := idp.serviceProvider(r, participant.ServiceProviderEntityID)
		if err != nil {
			skipLogoutParticipant(participant, err)

			continue
		}

		endpoint, err := idp.logoutRequestEndpoint(metadata, backChannelLogoutBindings...)
		if err != nil {
			skipLogoutParticipant(participant, err)

			continue
		}

		idp.sendSOAPLogoutRequest(r, state, i, endpoint)
	}
}

// newSOAPLogoutRequest returns the IdpLogoutRequest for the message of a SOAP request.
func newSOAPLogoutRequest(idp *IdentityProvider, r *http.Request, soap *soapRequest) *IdpLogoutRequest {
	return &IdpLogoutRequest{
		IDP:           idp,
		HTTPRequest:   r,
		RequestBuffer: soap.Body,
		Now:           TimeNow(),
		binding:       SOAPBinding,
	}
}

// discardResponseWriter is handed to TerminateSession on the back channel: headers set on it are dropped.
type discardResponseWriter struct{ header http.Header }

// Header implements [http.ResponseWriter].
func (w *discardResponseWriter) Header() http.Header {
	return w.header
}

// Write implements [http.ResponseWriter], and discards b.
func (w *discardResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

// WriteHeader implements [http.ResponseWriter], and does nothing.
func (w *discardResponseWriter) WriteHeader(int) {}

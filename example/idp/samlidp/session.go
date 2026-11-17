package samlidp

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"authelia.com/provider/saml"
)

var sessionMaxAge = time.Hour

// GetSession returns the *Session for this request.
//
// If the remote user has specified a username and password in the request
// then it is validated against the user database. If valid it sets a
// cookie and returns the newly created session object.
//
// If the remote user has specified invalid credentials then a login form
// is returned with an English-language toast telling the user their
// password was invalid.
//
// If a session cookie already exists and represents a valid session,
// then the session is returned
//
// If neither credentials nor a valid session cookie exist, this function
// sends a login form and returns nil.
func (s *Server) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	if hasCredentials(r) {
		return s.authenticate(w, r, req)
	}

	session, err := s.existingSession(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	if session != nil {
		return session
	}

	s.sendLoginForm(w, req, "")
	return nil
}

// GetPassiveSession implements saml.PassiveSessionProvider. It returns the existing session. This
// server only authenticates with a login form, so it can't satisfy ForceAuthn without interaction.
func (s *Server) GetPassiveSession(r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	if req.Request.ForceAuthn != nil && *req.Request.ForceAuthn {
		return nil
	}

	session, err := s.existingSession(r)
	if err != nil {
		s.logger.Printf("ERROR: cannot read session: %s", err)
		return nil
	}
	return session
}

// GetForcedSession implements saml.ForceAuthnSessionProvider. It authenticates with the credentials in
// the request or else sends a login form, and doesn't consider any existing session.
func (s *Server) GetForcedSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	if hasCredentials(r) {
		return s.authenticate(w, r, req)
	}

	s.sendLoginForm(w, req, "")
	return nil
}

// hasCredentials returns true if the request contains login credentials.
func hasCredentials(r *http.Request) bool {
	return r.Method == "POST" && r.PostForm.Get("user") != ""
}

// authenticate creates a session from the credentials in the request, or else sends a login form with
// an English-language toast telling the user their password was invalid and returns nil.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	// Credentials from another site would log the browser in as a user of that site's choosing.
	// Service providers post their requests from their own sites, so only a post with credentials
	// is checked.
	if err := s.checkLoginOrigin(r); err != nil {
		s.logger.Printf("ERROR: refused credentials from another origin: %s", err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return nil
	}

	user := User{}
	if err := s.Store.Get(fmt.Sprintf("/users/%s", r.PostForm.Get("user")), &user); err != nil {
		s.logger.Printf("ERROR: User '%s' doesn't exists", r.PostForm.Get("user"))
		s.sendLoginForm(w, req, "Invalid username or password")
		return nil
	}

	if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(r.PostForm.Get("password"))); err != nil {
		s.logger.Printf("ERROR: Invalid password for user '%s'", r.PostForm.Get("user"))
		s.sendLoginForm(w, req, "Invalid username or password")
		return nil
	}

	session := &saml.Session{
		ID:         base64.StdEncoding.EncodeToString(randomBytes(32)),
		NameID:     user.Email,
		CreateTime: saml.TimeNow(),
		ExpireTime: saml.TimeNow().Add(sessionMaxAge),
		Index:      hex.EncodeToString(randomBytes(32)),
		UserName:   user.Name,
		// nolint:gocritic // Groups should be a slice here.
		Groups:                user.Groups[:],
		UserEmail:             user.Email,
		UserCommonName:        user.CommonName,
		UserSurname:           user.Surname,
		UserGivenName:         user.GivenName,
		UserScopedAffiliation: user.ScopedAffiliation,
	}
	stored := storedSession{Session: *session, UserRevision: user.Revision}
	if err := s.Store.Put(fmt.Sprintf("/sessions/%s", session.ID), &stored); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	http.SetCookie(w, s.sessionCookie(r, session.ID, int(sessionMaxAge.Seconds())))

	s.logger.Printf("User '%s' authenticated successfully", r.PostForm.Get("user"))
	return session
}

// checkLoginOrigin returns an error if a browser posted the request from another origin. Browsers
// which don't send Sec-Fetch-Site have their Origin compared with the configured URL, scheme
// included, rather than with the Host header or forwarded headers, which the client or a proxy
// chooses. A request with neither header isn't from a browser that could be made to send it.
func (s *Server) checkLoginOrigin(r *http.Request) error {
	switch site := r.Header.Get("Sec-Fetch-Site"); site {
	case "same-origin", "none":
		return nil
	case "":
	default:
		return fmt.Errorf("Sec-Fetch-Site is %q", site)
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	want := s.IDP.SSOURL.Scheme + "://" + s.IDP.SSOURL.Host
	if !strings.EqualFold(origin, want) {
		return fmt.Errorf("origin %q is not %q", origin, want)
	}
	return nil
}

// existingSession returns the session of the cookie in the request, or nil if it doesn't have a
// current one.
func (s *Server) existingSession(r *http.Request) (*saml.Session, error) {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return nil, nil //nolint:nilerr // A missing cookie means that there is no session.
	}

	stored := storedSession{}
	if err := s.Store.Get(fmt.Sprintf("/sessions/%s", sessionCookie.Value), &stored); err != nil {
		if err == ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	if saml.TimeNow().After(stored.ExpireTime) {
		return nil, nil
	}

	// The session asserts the details of the user when it was created, so it is only used while the
	// user is unchanged. A login which was in progress when the user changed stores a session after
	// the change has ended the others.
	user := User{}
	if err := s.Store.Get(fmt.Sprintf("/users/%s", stored.UserName), &user); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if user.Revision != stored.UserRevision {
		return nil, nil
	}

	// A session whose participants are closed is being logged out, or failed to end, and can't be sent an
	// assertion, so the user authenticates again to a new session.
	var closed bool
	if err := s.Store.Get(fmt.Sprintf("/session-participants-closed/%s", stored.ID), &closed); err == nil {
		return nil, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return &stored.Session, nil
}

// storedSession is a session as it is stored, with the revision of the user it was created from. It
// reads as a saml.Session.
type storedSession struct {
	saml.Session
	UserRevision string `json:",omitempty"`
}

var defaultLoginFormTemplate = template.Must(template.New("saml-post-form").Parse(`` +
	`<html>` +
	`<p>{{.Toast}}</p>` +
	`<form method="post" action="{{.URL}}">` +
	`<input type="text" name="user" placeholder="user" value="" />` +
	`<input type="password" name="password" placeholder="password" value="" />` +
	`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
	`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
	`{{if .RedirectQuery}}<input type="hidden" name="SAMLRedirectQuery" value="{{.RedirectQuery}}" />{{end}}` +
	`<input type="submit" value="Log In" />` +
	`</form>` +
	`</html>`))

// sendLoginForm produces a form which requests a username and password and directs the user
// back to the IDP authorize URL to restart the SAML login flow, this time establishing a
// session based on the credentials that were provided.
func (s *Server) sendLoginForm(w http.ResponseWriter, req *saml.IdpAuthnRequest, toast string) {
	tmpl := s.LoginFormTemplate
	if tmpl == nil {
		tmpl = defaultLoginFormTemplate
	}
	values := req.ResumeFormValues()
	data := struct {
		Toast         string
		URL           string
		SAMLRequest   string
		RelayState    string
		RedirectQuery string
	}{
		Toast:         toast,
		URL:           loginFormURL(req),
		SAMLRequest:   values.Get("SAMLRequest"),
		RelayState:    values.Get("RelayState"),
		RedirectQuery: values.Get(saml.RedirectQueryFormField),
	}

	if err := tmpl.Execute(w, data); err != nil {
		panic(err)
	}
}

// loginFormURL returns where the login form posts to, which resumes whichever flow is in progress
// once the session exists.
func loginFormURL(req *saml.IdpAuthnRequest) string {
	if len(req.RequestBuffer) != 0 {
		return req.IDP.SSOURL.String()
	}
	if req.HTTPRequest != nil {
		if shortcut := req.HTTPRequest.PathValue("shortcut"); shortcut != "" {
			// These are decoded values chosen by whoever wrote the link, so they are escaped rather
			// than cleaned to keep the form, and the password, on the shortcut's own path.
			u := req.IDP.LoginURL
			u.RawPath = u.EscapedPath()
			for _, segment := range []string{shortcut, req.HTTPRequest.PathValue("suffix")} {
				if segment != "" {
					u.Path += "/" + segment
					u.RawPath += "/" + url.PathEscape(segment)
				}
			}
			return u.String()
		}
	}
	return req.IDP.LoginURL.String()
}

// HandleLogin handles the `POST /login` and `GET /login` forms. If credentials are present
// in the request body, then they are validated. For valid credentials, the response is a
// 200 OK and the JSON session object. For invalid credentials, the HTML login prompt form
// is sent.
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	session := s.GetSession(w, r, &saml.IdpAuthnRequest{IDP: &s.IDP})
	if session == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(session); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// HandleListSessions handles the `GET /sessions/` request and responds with a JSON formatted list
// of session names.
func (s *Server) HandleListSessions(w http.ResponseWriter, _ *http.Request) {
	sessions, err := s.Store.List("/sessions/")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(struct {
		Sessions []string `json:"sessions"`
	}{Sessions: sessions})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// HandleGetSession handles the `GET /sessions/:id` request and responds with the session
// object in JSON format.
func (s *Server) HandleGetSession(w http.ResponseWriter, r *http.Request) {
	session := saml.Session{}
	err := s.Store.Get(fmt.Sprintf("/sessions/%s", r.PathValue("id")), &session)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(session); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// HandleDeleteSession handles the `DELETE /sessions/:id` request. It invalidates the
// specified session.
func (s *Server) HandleDeleteSession(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Delete(fmt.Sprintf("/sessions/%s", r.PathValue("id")))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sessionCookie returns the session cookie with the given value and MaxAge.
func (s *Server) sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	//nolint:gosec // Secure and SameSite are set below, from the request and the configured URL.
	return &http.Cookie{
		Name:     "session",
		Value:    value,
		MaxAge:   maxAge,
		HttpOnly: true,
		// r.URL.Scheme is empty on server requests. The configured URL covers TLS terminated
		// by a proxy.
		Secure:   r.TLS != nil || s.IDP.SSOURL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}
}

// GetLogoutSessions implements saml.LogoutSessionProvider. It returns the session of the cookie in the
// request, if the request names its principal and, when it lists any, its session index, and an error
// if it doesn't. Sessions in other browsers are not found.
//
// The cookie is SameSite=Lax, so a browser doesn't send it with the cross-site POST of the HTTP-POST
// binding. That request gets an error rather than a success that would leave the session in place,
// and service providers must use the HTTP-Redirect binding to end the session.
func (s *Server) GetLogoutSessions(r *http.Request, req *saml.IdpLogoutRequest) ([]*saml.Session, error) {
	if _, err := r.Cookie("session"); err != nil && r.Method == http.MethodPost {
		return nil, errors.New("the session cookie is not sent with a cross-site POST")
	}

	session, err := s.existingSession(r)
	if err != nil {
		return nil, err
	}

	if session == nil {
		return nil, nil
	}

	// A request that doesn't name the session is refused, as it is for the cross-site POST, rather than
	// reported as a success.
	if err := req.MatchesSession(session); err != nil {
		return nil, err
	}

	return []*saml.Session{session}, nil
}

// TerminateSession implements saml.LogoutSessionProvider. It deletes the session and its participants and clears the cookie.
func (s *Server) TerminateSession(w http.ResponseWriter, r *http.Request, session *saml.Session) error {
	// The session is deleted under the lock of AddSessionParticipant, which refuses a session that no longer exists.
	s.participantsMu.Lock()

	err := s.Store.Delete(fmt.Sprintf("/sessions/%s", session.ID))
	if err == nil {
		err = s.Store.Delete(fmt.Sprintf("/session-participants/%s", session.ID))
	}

	if err == nil {
		err = s.Store.Delete(fmt.Sprintf("/session-participants-closed/%s", session.ID))
	}

	s.participantsMu.Unlock()

	if err != nil {
		return err
	}

	http.SetCookie(w, s.sessionCookie(r, "", -1))

	return nil
}

// AddSessionParticipant implements saml.SessionParticipantProvider. Under the lock of CloseSessionParticipants it
// appends the participant to those stored for the session, unless the session has ended or its participants are
// closed.
func (s *Server) AddSessionParticipant(_ *http.Request, session *saml.Session, participant saml.SessionParticipant) error {
	s.participantsMu.Lock()
	defer s.participantsMu.Unlock()

	if err := s.Store.Get(fmt.Sprintf("/sessions/%s", session.ID), &saml.Session{}); errors.Is(err, ErrNotFound) {
		return errors.New("the session has ended")
	} else if err != nil {
		return err
	}

	var closed bool
	if err := s.Store.Get(fmt.Sprintf("/session-participants-closed/%s", session.ID), &closed); err == nil {
		return saml.ErrSessionParticipantsClosed
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}

	key := fmt.Sprintf("/session-participants/%s", session.ID)

	participants := make([]saml.SessionParticipant, 0, 1)
	if err := s.Store.Get(key, &participants); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	return s.Store.Put(key, append(participants, participant))
}

// CloseSessionParticipants implements saml.SessionParticipantProvider. Under the lock of AddSessionParticipant it
// marks the participants of the session closed and returns them. A closed session is no longer used for a login,
// and TerminateSession removes the mark with the session.
func (s *Server) CloseSessionParticipants(_ *http.Request, session *saml.Session) ([]saml.SessionParticipant, error) {
	s.participantsMu.Lock()
	defer s.participantsMu.Unlock()

	if err := s.Store.Put(fmt.Sprintf("/session-participants-closed/%s", session.ID), true); err != nil {
		return nil, err
	}

	var participants []saml.SessionParticipant
	if err := s.Store.Get(fmt.Sprintf("/session-participants/%s", session.ID), &participants); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	return participants, nil
}

// SaveLogoutState implements saml.LogoutStateProvider. Under a lock it stores the state only if it follows the
// stored revision, as the Store has no conditional write.
func (s *Server) SaveLogoutState(_ *http.Request, state *saml.LogoutState) error {
	s.logoutStatesMu.Lock()
	defer s.logoutStatesMu.Unlock()

	key := fmt.Sprintf("/logout-states/%s", state.ID)

	stored := &saml.LogoutState{}

	switch err := s.Store.Get(key, stored); {
	case errors.Is(err, ErrNotFound):
		if state.Revision != 1 {
			return saml.ErrLogoutStateConflict
		}
	case err != nil:
		return err
	case stored.Revision+1 != state.Revision:
		return saml.ErrLogoutStateConflict
	}

	return s.Store.Put(key, state)
}

// LoadLogoutState implements saml.LogoutStateProvider. It returns [os.ErrNotExist] if there is no such state.
func (s *Server) LoadLogoutState(_ *http.Request, id string) (*saml.LogoutState, error) {
	state := &saml.LogoutState{}
	if err := s.Store.Get(fmt.Sprintf("/logout-states/%s", id), state); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, os.ErrNotExist
		}

		return nil, err
	}

	return state, nil
}

// DeleteLogoutState implements saml.LogoutStateProvider.
func (s *Server) DeleteLogoutState(_ *http.Request, id string) error {
	s.logoutStatesMu.Lock()
	defer s.logoutStatesMu.Unlock()

	return s.Store.Delete(fmt.Sprintf("/logout-states/%s", id))
}

// HandleLogout handles `POST /logout/start`. It logs out the browser of the cookie's session, and of every
// service provider it signed into, and returns to `/`. It is a POST that must come from the same origin, so
// that another site can't log the user out with a link or a redirect.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.checkLoginOrigin(r); err != nil {
		s.logger.Printf("ERROR: refused logout from another origin: %s", err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)

		return
	}

	session, err := s.existingSession(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if session == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if err := s.IDP.StartLogout(w, r, session, "/"); err != nil {
		s.logger.Printf("ERROR: cannot start logout: %s", err)

		// The session was ended, so the browser is logged out here even though no service provider was told.
		if errors.Is(err, saml.ErrLogoutNotPropagated) {
			http.Redirect(w, r, "/", http.StatusFound)

			return
		}

		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

var (
	_ saml.LogoutSessionProvider      = (*Server)(nil)
	_ saml.SessionParticipantProvider = (*Server)(nil)
	_ saml.LogoutStateProvider        = (*Server)(nil)
)

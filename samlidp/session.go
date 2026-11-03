package samlidp

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
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
	if err := s.Store.Put(fmt.Sprintf("/sessions/%s", session.ID), &session); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	//nolint:gosec // Secure and SameSite are set below, from the request and the configured URL.
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.ID,
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		// r.URL.Scheme is empty on server requests. The configured URL covers TLS terminated
		// by a proxy.
		Secure:   r.TLS != nil || s.IDP.SSOURL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	s.logger.Printf("User '%s' authenticated successfully", r.PostForm.Get("user"))
	return session
}

// existingSession returns the session of the cookie in the request, or nil if it doesn't have a
// current one.
func (s *Server) existingSession(r *http.Request) (*saml.Session, error) {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return nil, nil //nolint:nilerr // A missing cookie means that there is no session.
	}

	session := &saml.Session{}
	if err := s.Store.Get(fmt.Sprintf("/sessions/%s", sessionCookie.Value), session); err != nil {
		if err == ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	if saml.TimeNow().After(session.ExpireTime) {
		return nil, nil
	}
	return session, nil
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
	data := struct {
		Toast         string
		URL           string
		SAMLRequest   string
		RelayState    string
		RedirectQuery string
	}{
		Toast:         toast,
		URL:           loginFormURL(req),
		SAMLRequest:   base64.StdEncoding.EncodeToString(req.RequestBuffer),
		RelayState:    req.RelayState,
		RedirectQuery: req.RedirectQuery,
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

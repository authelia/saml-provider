package samlidp

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"authelia.com/provider/saml"
)

// User represents a stored user. The data here are used to
// populate user once the user has authenticated.
type User struct {
	Name              string   `json:"name"`
	PlaintextPassword *string  `json:"password,omitempty"` // not stored
	HashedPassword    []byte   `json:"hashed_password,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Email             string   `json:"email,omitempty"`
	CommonName        string   `json:"common_name,omitempty"`
	Surname           string   `json:"surname,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	ScopedAffiliation string   `json:"scoped_affiliation,omitempty"`

	// Revision changes whenever the user is stored through HandlePutUser, and is not taken from the
	// request. A session from another revision is not used.
	Revision string `json:"revision,omitempty"`
}

// HandleListUsers handles the `GET /users/` request and responds with a JSON formatted list
// of user names.
func (s *Server) HandleListUsers(w http.ResponseWriter, _ *http.Request) {
	users, err := s.Store.List("/users/")
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(struct {
		Users []string `json:"users"`
	}{Users: users})
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// HandleGetUser handles the `GET /users/:id` request and responds with the user object in JSON
// format. The HashedPassword and Revision fields are excluded.
func (s *Server) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	user := User{}
	err := s.Store.Get(fmt.Sprintf("/users/%s", r.PathValue("id")), &user)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	user.HashedPassword = nil
	user.Revision = ""
	if err := json.NewEncoder(w).Encode(user); err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// HandlePutUser handles the `PUT /users/:id` request. It accepts a JSON formatted user object in
// the request body and stores it. If the PlaintextPassword field is present then it is hashed
// and stored in HashedPassword. If the PlaintextPassword field is not present then
// HashedPassword retains it's stored value.
func (s *Server) HandlePutUser(w http.ResponseWriter, r *http.Request) {
	user := User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	user.Name = r.PathValue("id")

	// The email is the NameID of the user, so it must not be another user's.
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	if user.Email != "" {
		owner, err := s.emailOwner(user.Email, user.Name)
		if err != nil {
			s.logger.Printf("ERROR: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if owner != "" {
			s.logger.Printf("ERROR: the email of user %q is already the email of user %q", user.Name, owner)
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}
	}

	if user.PlaintextPassword != nil {
		var err error
		user.HashedPassword, err = bcrypt.GenerateFromPassword([]byte(*user.PlaintextPassword), bcrypt.DefaultCost)
		if err != nil {
			s.logger.Printf("ERROR: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	} else {
		existingUser := User{}
		err := s.Store.Get(fmt.Sprintf("/users/%s", r.PathValue("id")), &existingUser)
		switch err {
		case nil:
			user.HashedPassword = existingUser.HashedPassword
		case ErrNotFound:
			// nop
		default:
			s.logger.Printf("ERROR: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
	user.PlaintextPassword = nil
	user.Revision = rand.Text()

	err := s.Store.Put(fmt.Sprintf("/users/%s", r.PathValue("id")), &user)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err := s.endUserSessions(user.Name); err != nil {
		s.logger.Printf("ERROR: cannot end the sessions of the user: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteUser handles the `DELETE /users/:id` request.
func (s *Server) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Delete(fmt.Sprintf("/users/%s", r.PathValue("id")))
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err := s.endUserSessions(r.PathValue("id")); err != nil {
		s.logger.Printf("ERROR: cannot end the sessions of the user: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// endUserSessions deletes the stored sessions of the user, whose details they would otherwise keep
// asserting after the user is changed or deleted. A session it misses, such as one a login stores
// while it runs, is still refused because its user revision is out of date.
func (s *Server) endUserSessions(name string) error {
	ids, err := s.Store.List("/sessions/")
	if err != nil {
		return err
	}
	for _, id := range ids {
		session := saml.Session{}
		if err := s.Store.Get(fmt.Sprintf("/sessions/%s", id), &session); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return err
		}
		if session.UserName != name {
			continue
		}
		if err := s.Store.Delete(fmt.Sprintf("/sessions/%s", id)); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}

// emailOwner returns the name of a user other than except whose email is email, ignoring case, or ""
// if there is none.
func (s *Server) emailOwner(email, except string) (string, error) {
	names, err := s.Store.List("/users/")
	if err != nil {
		return "", err
	}
	for _, name := range names {
		if name == except {
			continue
		}
		other := User{}
		if err := s.Store.Get(fmt.Sprintf("/users/%s", name), &other); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return "", err
		}
		if strings.EqualFold(other.Email, email) {
			return name, nil
		}
	}
	return "", nil
}

// checkUserEmails returns an error if two stored users have the same email, which would make them
// one principal at every service provider.
func (s *Server) checkUserEmails() error {
	names, err := s.Store.List("/users/")
	if err != nil {
		return err
	}
	slices.Sort(names)
	type userEmail struct{ name, email string }
	emails := make([]userEmail, 0, len(names))
	for _, name := range names {
		user := User{}
		if err := s.Store.Get(fmt.Sprintf("/users/%s", name), &user); err != nil {
			return err
		}
		if user.Email == "" {
			continue
		}
		for _, other := range emails {
			if strings.EqualFold(other.email, user.Email) {
				return fmt.Errorf("users %q and %q have the same email, which is their NameID: change one of them in the store", other.name, name)
			}
		}
		emails = append(emails, userEmail{name: name, email: user.Email})
	}
	return nil
}

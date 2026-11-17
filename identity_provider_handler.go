package saml

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"net/url"
)

// Handler returns an [http.Handler] that serves the metadata and SSO URLs, and each of the other URLs that is set:
// LogoutURL, SOAPLogoutURL, ECPURL, ArtifactResolutionURL, AttributeServiceURL, AuthnQueryServiceURL,
// AssertionIDRequestServiceURL, ManageNameIDURL, SOAPManageNameIDURL and NameIDMappingURL. A URL with an empty path
// is served at "/".
//
// URLs may share a path, and Handler doesn't panic when they do. A request that is not a SOAP request, which is a
// POST with a text/xml body that no front-channel binding sends, goes to the front-channel service of its path:
// ServeMetadata, ServeSSO, ServeSLO or ServeManageNameID, or the first of them in that order if several share the
// path. A SOAP request
// goes to the service on the SOAP binding of its path. If several of those share the path, the body is read, up to
// the size that a SOAP request may have, and the request goes to the service of the SAML message in the Body of
// the envelope: a LogoutRequest to ServeSOAPLogout, an AuthnRequest to ServeECP, an ArtifactResolve to
// ServeArtifactResolution, an AttributeQuery to ServeAttributeQuery, an AuthnQuery to ServeAuthnQuery, an
// AssertionIDRequest to ServeAssertionIDRequest, a ManageNameIDRequest to ServeSOAPManageNameID and a
// NameIDMappingRequest to ServeNameIDMapping. The service reads the body again, and makes every check on the
// request itself, so nothing is trusted because of where a request was sent.
//
// A SOAP request that can't be read, or whose message has no service at the path, goes to the first service on the
// SOAP binding there, in the order above, which refuses it as it would at a path of its own. So does any other
// request at a path with no front-channel service.
func (idp *IdentityProvider) Handler() http.Handler {
	routes := &handlerRoutes{byPath: map[string]*handlerRoute{}}

	routes.addFront(idp.MetadataURL, idp.ServeMetadata)
	routes.addFront(idp.SSOURL, idp.ServeSSO)

	if idp.LogoutURL.String() != "" {
		routes.addFront(idp.LogoutURL, idp.ServeSLO)
	}

	if idp.SOAPLogoutURL.String() != "" {
		routes.addSOAP(idp.SOAPLogoutURL, "LogoutRequest", idp.ServeSOAPLogout)
	}

	if idp.ECPURL.String() != "" {
		routes.addSOAP(idp.ECPURL, "AuthnRequest", idp.ServeECP)
	}

	if idp.artifactEnabled() {
		routes.addSOAP(idp.ArtifactResolutionURL, "ArtifactResolve", idp.ServeArtifactResolution)
	}

	if idp.AttributeServiceURL.String() != "" {
		routes.addSOAP(idp.AttributeServiceURL, attributeQueryMessage, idp.ServeAttributeQuery)
	}

	if idp.AuthnQueryServiceURL.String() != "" {
		routes.addSOAP(idp.AuthnQueryServiceURL, authnQueryMessage, idp.ServeAuthnQuery)
	}

	if idp.AssertionIDRequestServiceURL.String() != "" {
		routes.addSOAP(idp.AssertionIDRequestServiceURL, assertionIDRequestMessage, idp.ServeAssertionIDRequest)
	}

	if idp.ManageNameIDURL.String() != "" {
		routes.addFront(idp.ManageNameIDURL, idp.ServeManageNameID)
	}

	if idp.SOAPManageNameIDURL.String() != "" {
		routes.addSOAP(idp.SOAPManageNameIDURL, "ManageNameIDRequest", idp.ServeSOAPManageNameID)
	}

	if idp.NameIDMappingURL.String() != "" {
		routes.addSOAP(idp.NameIDMappingURL, "NameIDMappingRequest", idp.ServeNameIDMapping)
	}

	mux := http.NewServeMux()

	for _, path := range routes.paths {
		mux.Handle(path, routes.byPath[path])
	}

	return mux
}

// handlerRoutes are the services that Handler serves, by path, so that each path is given to the mux once however
// many URLs share it.
type handlerRoutes struct {
	// paths are the keys of byPath in the order they were added.
	paths  []string
	byPath map[string]*handlerRoute
}

// route returns the route of the path of u, which it adds if there is none.
func (routes *handlerRoutes) route(u url.URL) *handlerRoute {
	path := handlerPath(u)

	route, ok := routes.byPath[path]
	if !ok {
		route = &handlerRoute{}
		routes.byPath[path] = route
		routes.paths = append(routes.paths, path)
	}

	return route
}

// addFront makes serve the front-channel service at the path of u, unless it already has one.
func (routes *handlerRoutes) addFront(u url.URL, serve http.HandlerFunc) {
	if route := routes.route(u); route.front == nil {
		route.front = serve
	}
}

// addSOAP adds serve as the service on the SOAP binding at the path of u for the SAML protocol message with the
// local name.
func (routes *handlerRoutes) addSOAP(u url.URL, message string, serve http.HandlerFunc) {
	route := routes.route(u)
	route.soap = append(route.soap, handlerSOAPService{message: message, serve: serve})
}

// handlerSOAPService is a service on the SOAP binding, and the local name of the SAML protocol message it is for.
type handlerSOAPService struct {
	message string
	serve   http.HandlerFunc
}

// handlerRoute is what Handler serves at one path: at most one front-channel service, and any number of services
// on the SOAP binding, of which it has at least one of either.
type handlerRoute struct {
	front http.HandlerFunc
	soap  []handlerSOAPService
}

// ServeHTTP sends r to the service of the route that it is for, as Handler describes.
func (route *handlerRoute) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case len(route.soap) == 0:
		route.front(w, r)
	case !isSOAPRequest(r):
		if route.front != nil {
			route.front(w, r)

			return
		}

		// The service answers that this is not a request of its binding.
		route.soap[0].serve(w, r)
	case len(route.soap) == 1:
		route.soap[0].serve(w, r)
	default:
		route.soapService(r)(w, r)
	}
}

// soapService returns the service on the SOAP binding for the message in the envelope of r, or the first service if
// there is none or the envelope can't be read. It reads the body of r, and replaces it with one that the service
// can read again. No more is read than a SOAP request may have: a longer body is left to the service, which
// refuses it for its size.
func (route *handlerRoute) soapService(r *http.Request) http.HandlerFunc {
	fallback := route.soap[0].serve

	if r.Body == nil {
		return fallback
	}

	body := r.Body

	buf, err := io.ReadAll(io.LimitReader(body, soapMaxMessageSize+1))

	r.Body = &handlerBody{Reader: io.MultiReader(bytes.NewReader(buf), body), Closer: body}

	if err != nil || len(buf) > soapMaxMessageSize {
		return fallback
	}

	_, _, message, err := parseSOAPEnvelope(buf)
	if err != nil || message.NamespaceURI() != samlProtocolNS {
		return fallback
	}

	for _, service := range route.soap {
		if service.message == message.Tag {
			return service.serve
		}
	}

	return fallback
}

// handlerBody is a request body whose start has been read and is read again.
type handlerBody struct {
	io.Reader
	io.Closer
}

// handlerPath returns the path of u to serve it at on a mux, which is "/" when the path is empty.
func handlerPath(u url.URL) string {
	if u.Path == "" {
		return "/"
	}

	return u.Path
}

// isSOAPRequest reports whether r is a POST with a text/xml body, which a SOAP 1.1 request is, and which no
// front-channel binding sends.
func isSOAPRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))

	return err == nil && mediaType == "text/xml"
}

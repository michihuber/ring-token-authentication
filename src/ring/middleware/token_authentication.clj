(ns ring.middleware.token-authentication
  "HTTP token authentication middleware for ring."
  {:author "Jason Stewart"})

(defn- parse-token
  [request]
  (let [auth ((:headers request) "authorization")]
    (and auth (last (re-find #"Token token=(.*)$" auth)))))

(defn token-authentication-request
  "Authenticates the given request against using a fn (f) that accepts a single
  string parameter that is the token parsed from the authentication header.
  The return value is added to the request with the keyword :token-authentication.
  true indicates successful auth, while false or nil indicates failure.
  failure."
  [request f]
  (let [token (parse-token request)]
    (assoc request :token-authentication
           (and token (f (str token))))))

(defn token-authentication-failure
  "Returns a 401 unauthorized, along with body text that indicates the same.
   alternatively overridden by 'custom-response'
   (:status, :body, keys or :headers map must be supplied when overriding"
  [custom-response]
  (let [resp    {:status 401 :body "unauthorized"}
        headers {"WWW-Authenticate" "Token realm=\"Application\""}]
    (assoc (merge resp custom-response)
      :headers (merge (:headers resp) headers))))

(defn wrap-token-parsing
  "Parses the authentication token from the authorization header (if
  available) and inserts it under the :token-authentication key in the
  request map."
  [handler]
  (fn [request]
    (handler (assoc request :token-authentication (parse-token request)))))

(defn wrap-token-authentication
  "Wrap the response with a REST token authentication.

  calls the authentication function with the authorization token found in
  the headers. If the token is invalid, a 401 response is returned and the
  body set to the string 'unauthorized'. This is overridable. Additionally,
  the WWW-Authenticate: header is set in accordance with token auth drafts."
  [handler authenticate & [custom-response]]
  (fn [request]
    (let [token-req (token-authentication-request request authenticate)]
      (if (:token-authentication token-req)
        (handler token-req)
        (token-authentication-failure custom-response)))))

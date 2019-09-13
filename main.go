package main

import (
  "net/http"
  "strings"
  "errors"
  "net/url"
  "os"
  "time"
  "crypto/rand"
  "encoding/base64"
  "encoding/gob"
  "golang.org/x/net/context"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  "github.com/gofrs/uuid"
  "github.com/gin-contrib/sessions"
  "github.com/gin-contrib/sessions/cookie"
  oidc "github.com/coreos/go-oidc"
  "github.com/pborman/getopt"

  "github.com/charmixer/aapui/config"
  "github.com/charmixer/aapui/environment"
  "github.com/charmixer/aapui/controllers"
)

const app = "aapui"

var (
  logDebug int // Set to 1 to enable debug
  logFormat string // Current only supports default and json

  log *logrus.Logger

  appFields logrus.Fields
)

func init() {
  log = logrus.New();

  err := config.InitConfigurations()
  if err != nil {
    log.Panic(err.Error())
    return
  }

  logDebug = config.GetInt("log.debug")
  logFormat = config.GetString("log.format")

  // We only have 2 log levels. Things developers care about (debug) and things the user of the app cares about (info)
  log = logrus.New();
  if logDebug == 1 {
    log.SetLevel(logrus.DebugLevel)
  } else {
    log.SetLevel(logrus.InfoLevel)
  }
  if logFormat == "json" {
    log.SetFormatter(&logrus.JSONFormatter{})
  }

  appFields = logrus.Fields{
    "appname": app,
    "log.debug": logDebug,
    "log.format": logFormat,
  }

  gob.Register(&oauth2.Token{}) // This is required to make session in idpui able to persist tokens.
  gob.Register(&oidc.IDToken{})
  //gob.Register(&idp.Profile{})
  gob.Register(make(map[string][]string))
}

func main() {

  provider, err := oidc.NewProvider(context.Background(), config.GetString("hydra.public.url") + "/")
  if err != nil {
    logrus.WithFields(appFields).Panic("oidc.NewProvider" + err.Error())
    return
  }

  hydraConfig := &oauth2.Config{
    ClientID:     config.GetString("oauth2.client.id"),
    ClientSecret: config.GetString("oauth2.client.secret"),
    Endpoint:     provider.Endpoint(),
    RedirectURL:  config.GetString("oauth2.callback"),
    Scopes:       config.GetStringSlice("oauth2.scopes.required"),
  }

  // CpFe needs to be able as an App using client_id to access AapApi endpoints. Using client credentials flow
  aapConfig := &clientcredentials.Config{
    ClientID:  config.GetString("oauth2.client.id"),
    ClientSecret: config.GetString("oauth2.client.secret"),
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.GetStringSlice("oauth2.scopes.required"),
    EndpointParams: url.Values{"audience": {"aap"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  // Setup app state variables. Can be used in handler functions by doing closures see exchangeAuthorizationCodeCallback
  env := &environment.State{
    Provider: provider,
    AapApiConfig: aapConfig,
    HydraConfig: hydraConfig,
  }

  //optServe := getopt.BoolLong("serve", 0, "Serve application")
  optHelp := getopt.BoolLong("help", 0, "Help")
  getopt.Parse()

  if *optHelp {
    getopt.Usage()
    os.Exit(0)
  }

  //if *optServe {
    serve(env)
  /*} else {
    getopt.Usage()
    os.Exit(0)
  }*/

}

func serve(env *environment.State) {
  // Setup routes to use, this defines log for debug log
  routes := map[string]environment.Route{
    "/":          environment.Route{URL: "/",          LogId: "aapui://"},
    "/authorize": environment.Route{URL: "/authorize", LogId: "aapui://authorize"},
    "/dashboard": environment.Route{URL: "/dashboard", LogId: "aapui://dashboard"},
    "/authorizations": environment.Route{URL: "/authorizations", LogId: "aapui://authorizations"},
    "/access": environment.Route{URL: "/access", LogId: "aapui://access"},
    "/access/new": environment.Route{URL: "/access/new", LogId: "aapui://access/new"},
    "/callback":   environment.Route{URL: "/callback", LogId: "aapui://callback"},
  }

  r := gin.New() // Clean gin to take control with logging.
  r.Use(gin.Recovery())

  r.Use(requestId())
  r.Use(RequestLogger(env))

  store := cookie.NewStore([]byte(config.GetString("session.authKey")))
  // Ref: https://godoc.org/github.com/gin-gonic/contrib/sessions#Options
  store.Options(sessions.Options{
    MaxAge: 86400,
    Path: "/",
    Secure: true,
    HttpOnly: true,
  })
  r.Use(sessions.Sessions(environment.SessionStoreKey, store))

  // Use CSRF on all our forms.
  adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.GetString("csrf.authKey")), csrf.Secure(true)))
  // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

  r.Static("/public", "public")
  r.LoadHTMLGlob("views/*")


  ep := r.Group("/")
  ep.Use(adapterCSRF)
  {
    // FIXME: Should these endpoints be protected? aka requiring authentication before access?
    ep.GET(routes["/"].URL, controllers.ShowAuthorization(env, routes["/"]))

    ep.GET(routes["/callback"].URL, controllers.ExchangeAuthorizationCodeCallback(env, routes["/callback"])) // token exhange endpoint.

    ep.GET(routes["/authorize"].URL, controllers.ShowAuthorization(env, routes["/authorize"]))
    ep.POST(routes["/authorize"].URL, controllers.SubmitAuthorization(env, routes["/authorize"]))

    ep.GET(routes["/dashboard"].URL, AuthenticationAndAuthorizationRequired(env, routes["/dashboard"], "openid"), controllers.ShowDashboard(env, routes["/dashboard"]))
    ep.GET(routes["/authorizations"].URL, AuthenticationAndAuthorizationRequired(env, routes["/dashboard"], "openid"), controllers.ShowAuthorizations(env, routes["/authorizations"]))

    ep.GET(routes["/access"].URL, AuthenticationAndAuthorizationRequired(env, routes["/access"], "openid"), controllers.ShowAccess(env, routes["/access"]))

    ep.GET(routes["/access/new"].URL, AuthenticationAndAuthorizationRequired(env, routes["/access/new"], "openid"), controllers.ShowAccessNew(env, routes["/access/new"]))
    ep.POST(routes["/access/new"].URL, AuthenticationAndAuthorizationRequired(env, routes["/access/new"], "openid"), controllers.SubmitAccessNew(env, routes["/access/new"]))

  }

  r.RunTLS(":" + config.GetString("serve.public.port"), config.GetString("serve.tls.cert.path"), config.GetString("serve.tls.key.path"))
}

func RequestLogger(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    // Start timer
    start := time.Now()
    path := c.Request.URL.Path
    raw := c.Request.URL.RawQuery

    var requestId string = c.MustGet(environment.RequestIdKey).(string)
    requestLog := log.WithFields(appFields).WithFields(logrus.Fields{
      "request.id": requestId,
    })
    c.Set(environment.LogKey, requestLog)

    c.Next()

    // Stop timer
    stop := time.Now()
    latency := stop.Sub(start)

    ipData, err := getRequestIpData(c.Request)
    if err != nil {
      log.WithFields(appFields).WithFields(logrus.Fields{
        "func": "RequestLogger",
      }).Debug(err.Error())
    }

    forwardedForIpData, err := getForwardedForIpData(c.Request)
    if err != nil {
      log.WithFields(appFields).WithFields(logrus.Fields{
        "func": "RequestLogger",
      }).Debug(err.Error())
    }

    method := c.Request.Method
    statusCode := c.Writer.Status()
    errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

    bodySize := c.Writer.Size()

    var fullpath string = path
    if raw != "" {
      fullpath = path + "?" + raw
    }

    log.WithFields(appFields).WithFields(logrus.Fields{
      "latency": latency,
      "forwarded_for.ip": forwardedForIpData.Ip,
      "forwarded_for.port": forwardedForIpData.Port,
      "ip": ipData.Ip,
      "port": ipData.Port,
      "method": method,
      "status": statusCode,
      "error": errorMessage,
      "body_size": bodySize,
      "path": fullpath,
      "request.id": requestId,
    }).Info("")
  }
  return gin.HandlerFunc(fn)
}

// # Authentication and Authorization
// Gin middleware to secure idp fe endpoints using oauth2.
//
// ## QTNA - Questions that need answering before granting access to a protected resource
// 1. Is the user or client authenticated? Answered by the process of obtaining an access token.
// 2. Is the access token expired?
// 3. Is the access token granted the required scopes?
// 4. Is the user or client giving the grants in the access token authorized to operate the scopes granted?
// 5. Is the access token revoked?
func AuthenticationAndAuthorizationRequired(env *environment.State, route environment.Route, requiredScopes ...string) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "AuthenticationAndAuthorizationRequired",
    })

    // Authentication
    token, err := authenticationRequired(env, c, route, log)
    if err != nil {
      // Require authentication to access resources. Init oauth2 Authorization code flow with idpui as the client.
      log.Debug(err.Error())

      initUrl, err := startAuthenticationSession(env, c, route, log)
      if err != nil {
        log.Debug(err.Error())
        c.HTML(http.StatusInternalServerError, "", gin.H{"error": err.Error()})
        c.Abort()
        return
      }
      c.Redirect(http.StatusFound, initUrl.String())
      c.Abort()
      return
    }
    c.Set(environment.AccessTokenKey, token) // Authenticated, so use it forward.

    // Authorization
    _ /* grantedScopes */, err = authorizationRequired(env, c, route, log, requiredScopes)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    log.WithFields(logrus.Fields{"fixme":1}).Debug("Missing id_token. Write code to find it correctly")
    idToken := &oauth2.Token{}
    c.Set(environment.IdTokenKey, idToken) // Authorized

    c.Next() // Authentication and authorization successful, continue.
    return
  }
  return gin.HandlerFunc(fn)
}

func authenticationRequired(env *environment.State, c *gin.Context, route environment.Route, log *logrus.Entry) (*oauth2.Token, error) {
  session := sessions.Default(c)

  log = log.WithFields(logrus.Fields{
    "func": "authenticationRequired",
  })

  logWithBearer := log.WithFields(logrus.Fields{"authorization": "bearer"})
  logWithSession := log.WithFields(logrus.Fields{"authorization": "session"})

  logWithBearer.Debug("Looking for access token")
  var token *oauth2.Token
  auth := c.Request.Header.Get("Authorization")
  split := strings.SplitN(auth, " ", 2)
  if len(split) == 2 || strings.EqualFold(split[0], "bearer") {
    logWithBearer.Debug("Found access token")
    token = &oauth2.Token{
      AccessToken: split[1],
      TokenType: split[0],
    }
    log = logWithBearer
  } else {
    logWithSession.Debug("Looking for access token")
    v := session.Get(environment.SessionTokenKey)
    if v != nil {
      token = v.(*oauth2.Token)
      logWithSession.Debug("Found access token")
    }
    log = logWithSession
  }

  tokenSource := env.HydraConfig.TokenSource(oauth2.NoContext, token)
  newToken, err := tokenSource.Token()
  if err != nil {
    return nil, err
  }

  if newToken.AccessToken != token.AccessToken {
    log.Debug("Refreshed access token. Session updated")
    session.Set(environment.SessionTokenKey, newToken)
    session.Save()
    token = newToken
  }
/*
  client := oauth2.NewClient(oauth2.NoContext, tokenSource)
  resp, err := client.Get(url)*/

  // See #2 of QTNA
  // https://godoc.org/golang.org/x/oauth2#Token.Valid
  if token.Valid() == true {
    log.Debug("Valid access token")

    // See #5 of QTNA
    log.WithFields(logrus.Fields{"fixme": 1, "qtna": 5}).Debug("Missing check against token-revoked-list to check if token is revoked") // Call token revoked list to check if token is revoked.

    return token, nil
  }

  // Deny by default
  return nil, errors.New("Invalid access token")
}

func authorizationRequired(env *environment.State, c *gin.Context, route environment.Route, log *logrus.Entry, requiredScopes []string) ([]string, error) {

  log = log.WithFields(logrus.Fields{
    "func": "authorizationRequired",
  })

  strRequiredScopes := strings.Join(requiredScopes, ",")
  log.WithFields(logrus.Fields{"scopes": strRequiredScopes}).Debug("Looking for required scopes");

  var grantedScopes []string

  // See #3 of QTNA
  log.WithFields(logrus.Fields{"fixme": 1, "qtna": 3}).Debug("Missing check if access token is granted the required scopes")

  /*aapClient := aap.NewAapApiClient(env.AapApiConfig)
  grantedScopes, err := aap.IsRequiredScopesGrantedForToken(config.aap.AuthorizationsUrl, aapClient, requiredScopes)
  if err != nil {
    return nil, err
  }*/

  // See #4 of QTNA
  log.WithFields(logrus.Fields{"fixme": 1, "qtna": 4}).Debug("Missing check if the user or client giving the grants in the access token  isauthorized to operate the granted scopes")

  strGrantedScopes := strings.Join(grantedScopes, ",")
  log.WithFields(logrus.Fields{"scopes": strGrantedScopes}).Debug("Found required scopes");
  return grantedScopes, nil
}
func startAuthenticationSession(env *environment.State, c *gin.Context, route environment.Route, log *logrus.Entry) (*url.URL, error) {
  var state string
  var err error

  log = log.WithFields(logrus.Fields{
    "func": "StartAuthentication",
  })

  // Redirect to after successful authentication
  redirectTo := c.Request.RequestURI

  // Always generate a new authentication session state
  session := sessions.Default(c)

  state, err = createRandomStringWithNumberOfBytes(64);
  if err != nil {
    log.Debug(err.Error())
    return nil, err
  }

  session.Set(environment.SessionStateKey, state)
  session.Set(state, redirectTo)
  err = session.Save()
  if err != nil {
    log.Debug(err.Error())
    return nil, err
  }

  logSession := log.WithFields(logrus.Fields{
    "redirect_to": redirectTo,
    "state": state,
  })
  logSession.Debug("Started session")
  authUrl := env.HydraConfig.AuthCodeURL(state)
  u, err := url.Parse(authUrl)
  return u, err
}

func requestId() gin.HandlerFunc {
  return func(c *gin.Context) {
    // Check for incoming header, use it if exists
    requestID := c.Request.Header.Get("X-Request-Id")

    // Create request id with UUID4
    if requestID == "" {
      uuid4, _ := uuid.NewV4()
      requestID = uuid4.String()
    }

    // Expose it for use in the application
    c.Set("RequestId", requestID)

    // Set X-Request-Id header
    c.Writer.Header().Set("X-Request-Id", requestID)
    c.Next()
  }
}

func createRandomStringWithNumberOfBytes(numberOfBytes int) (string, error) {
  st := make([]byte, numberOfBytes)
  _, err := rand.Read(st)
  if err != nil {
    return "", err
  }
  return base64.StdEncoding.EncodeToString(st), nil
}

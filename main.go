package main

import (
  "fmt"
  "net/http"
  "net/url"

  "golang.org/x/net/context"
  _ "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"

  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  "github.com/atarantini/ginrequestid"

  oidc "github.com/coreos/go-oidc"

  "golang-cp-fe/config"
  "golang-cp-fe/gateway/cpbe"
)

type authorizeForm struct {
    Consents []string `form:"consents[]"`
    Accept string `form:"accept"`
    Cancel string `form:"cancel"`
}

var (
  cpbeConfig *clientcredentials.Config
)

func init() {
  config.InitConfigurations()
}

const app = "cpfe"
func debugLog(app string, event string, msg string, requestId string) {
  if requestId == "" {
    fmt.Println(fmt.Sprintf("[app:%s][event:%s] %s", app, event, msg))
    return;
  }
  fmt.Println(fmt.Sprintf("[app:%s][request-id:%s][event:%s] %s", app, requestId, event, msg))
}

type CpFeEnv struct {
  Provider *oidc.Provider
  CpBeConfig *clientcredentials.Config
}

func main() {

  provider, err := oidc.NewProvider(context.Background(), config.Hydra.Url + "/")
  if err != nil {
    fmt.Println(err)
    return
  }

  // CpFe needs to be able as an App using client_id to access CpBe endpoints. Using client credentials flow
  cpbeConfig = &clientcredentials.Config{
    ClientID:  config.CpFe.ClientId,
    ClientSecret: config.CpFe.ClientSecret,
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.CpFe.RequiredScopes,
    EndpointParams: url.Values{"audience": {"cpbe"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  // Setup app state variables. Can be used in handler functions by doing closures see exchangeAuthorizationCodeCallback
  env := &CpFeEnv{
    Provider: provider,
    CpBeConfig: cpbeConfig,
  }

  r := gin.Default()
  r.Use(ginrequestid.RequestId())

  // Use CSRF on all our forms.
  adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.CpFe.CsrfAuthKey), csrf.Secure(true)))
  // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

  r.Static("/public", "public")
  r.LoadHTMLGlob("views/*")

  ep := r.Group("/")
  ep.Use(adapterCSRF)
  {
    r.GET("/", showAuthorization(env))
    r.GET("/authorize", showAuthorization(env))
    r.POST("/authorize", submitAuthorization(env))
  }

  r.RunTLS(":" + config.Self.Port, "/srv/certs/cpfe-cert.pem", "/srv/certs/cpfe-key.pem")
}

func showAuthorization(env *CpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    fmt.Println(fmt.Sprintf("[request-id:%s][event:showAuthorization]", c.MustGet("RequestId")))

    // comes from hydra redirect
    consentChallenge := c.Query("consent_challenge")
    if consentChallenge == "" {
      c.JSON(http.StatusNotFound, gin.H{"error": "Missing consent challenge"})
      c.Abort()
      return
    }

    cpbeClient := cpbe.NewCpBeClient(env.CpBeConfig)

    var authorizeRequest = cpbe.AuthorizeRequest{
      Challenge: consentChallenge,
    }
    authorizeResponse, err := cpbe.Authorize(config.CpBe.AuthorizationsAuthorizeUrl, cpbeClient, authorizeRequest)
    if err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if authorizeResponse.Authorized {
      c.Redirect(http.StatusFound, authorizeResponse.RedirectTo)
      c.Abort()
      return
    }

    var consents = make(map[int]map[string]string)
    for index, name := range authorizeResponse.RequestedScopes {
      // index is the index where we are
      // element is the element from someSlice for where we are
      consents[index] = map[string]string{
        "name": name,
      }
    }

    c.HTML(200, "authorize.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "requested_scopes": consents,
      "challenge": consentChallenge,
    })
  }
  return gin.HandlerFunc(fn)
}

func submitAuthorization(env *CpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    fmt.Println(fmt.Sprintf("[request-id:%s][event:submitAuthorization]", c.MustGet("RequestId")))
    var form authorizeForm
    c.Bind(&form)

    // comes from form post url
    challenge := c.Query("challenge")

    cpbeClient := cpbe.NewCpBeClient(env.CpBeConfig)

    if form.Accept != "" {
      authorizeRequest := cpbe.AuthorizeRequest{
        Challenge: challenge,
        GrantScopes: form.Consents,
      }
      authorizationsAuthorizeResponse, _ := cpbe.Authorize(config.CpBe.AuthorizationsAuthorizeUrl, cpbeClient, authorizeRequest)
      if  authorizationsAuthorizeResponse.Authorized {
        c.Redirect(302, authorizationsAuthorizeResponse.RedirectTo)
        c.Abort()
        return
      }
    }

    // Deny by default.
    rejectRequest := cpbe.RejectRequest{
      Challenge: challenge,
    }
    rejectResponse, _ := cpbe.Reject(config.CpBe.AuthorizationsRejectUrl, cpbeClient, rejectRequest)
    c.Redirect(302, rejectResponse.RedirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

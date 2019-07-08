package main

import (
  "fmt"
  "net/http"
  "net/url"

  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"

  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  "github.com/atarantini/ginrequestid"

  "golang-cp-fe/config"
  "golang-cp-fe/gateway/cpbe"
  "golang-cp-fe/gateway/cpfe"
)

type authorizeForm struct {
    Consents []string `form:"consents[]"`
    Accept string `form:"accept"`
    Cancel string `form:"cancel"`
}

var (
  cpbeClient *http.Client
)

func init() {
  config.InitConfigurations()
}

func main() {

  // Initialize the idp-be http client with client credentials token for use in the API.
  var cpbeClientCredentialsConfig *clientcredentials.Config = &clientcredentials.Config{
    ClientID:     config.CpFe.ClientId,
    ClientSecret: config.CpFe.ClientSecret,
    TokenURL:     config.Hydra.TokenUrl,
    Scopes:       config.CpFe.RequiredScopes,
    EndpointParams: url.Values{"audience": {"cpbe"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }
  cpbeToken, err := cpfe.RequestAccessTokenForCpBe(cpbeClientCredentialsConfig)
  if err != nil {
    fmt.Println("Unable to aquire cpbe access token. Error: " + err.Error())
    return
  }
  fmt.Println("Logging access token to cp-be. Do not do this in production")
  fmt.Println(cpbeToken) // FIXME Do not log this!!
  cpbeClient = cpbeClientCredentialsConfig.Client(oauth2.NoContext)

    r := gin.Default()
    //r.Use(logRequest())
    r.Use(ginrequestid.RequestId())

    // Use CSRF on all our forms.
    adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.CpFe.CsrfAuthKey), csrf.Secure(true)))
    // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

    r.Static("/public", "public")

    r.LoadHTMLGlob("views/*")

    r.GET("/", adapterCSRF, getAuthorizeHandler)
    r.GET("/authorize", adapterCSRF, getAuthorizeHandler)
    r.POST("/authorize", adapterCSRF, postAuthorizeHandler)

    r.RunTLS(":" + config.Self.Port, "/srv/certs/cpfe-cert.pem", "/srv/certs/cpfe-key.pem")
    //r.Run() // defaults to :8080, uses env PORT if set
}

func logRequest() gin.HandlerFunc {
  return func(c *gin.Context) {
    fmt.Println("Logging all requests. Do not do this in production it will leak tokens")
    fmt.Println(c.Request)
    c.Next()
  }
}

func getAuthorizeHandler(c *gin.Context) {
  fmt.Println(fmt.Sprintf("[request-id:%s][event:getAuthorizeHandler]", c.MustGet("RequestId")))

  // comes from hydra redirect
  consentChallenge := c.Query("consent_challenge")
  if consentChallenge == "" {
    c.JSON(http.StatusNotFound, gin.H{"error": "Missing consent challenge"})
    c.Abort()
    return
  }

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
  c.Abort()
}

func postAuthorizeHandler(c *gin.Context) {
  fmt.Println(fmt.Sprintf("[request-id:%s][event:postAuthorizeHandler]", c.MustGet("RequestId")))
  var form authorizeForm
  c.Bind(&form)

  // comes from form post url
  challenge := c.Query("challenge")

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

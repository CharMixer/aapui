package main

import (
  "github.com/gin-gonic/gin"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  "fmt"
  "net/http"
  "net/url"
  "golang-cp-fe/config"
  "golang-cp-fe/gateway/cpbe"
  "golang-cp-fe/gateway/cpfe"
)

type authorizeForm struct {
    Consents []string `form:"consents[]"`
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
  fmt.Println(cpbeToken) // FIXME Do not log this!!
  cpbeClient = cpbeClientCredentialsConfig.Client(oauth2.NoContext)

    r := gin.Default()

    // Use CSRF on all our forms.
    fmt.Println("Using insecure CSRF for devlopment. Do not do this in production")
    adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.CpFe.CsrfAuthKey), csrf.Secure(false)))
    // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

    r.Static("/public", "public")

    r.LoadHTMLGlob("views/*")

    r.GET("/", adapterCSRF, getAuthorizeHandler)
    r.GET("/authorize", adapterCSRF, getAuthorizeHandler)
    r.POST("/authorize", adapterCSRF, postAuthorizeHandler)

    r.Run() // defaults to :8080, uses env PORT if set
}

func getAuthorizeHandler(c *gin.Context) {
  // comes from hydra redirect
  consentChallenge := c.Query("consent_challenge")
  if consentChallenge == "" {
    c.JSON(http.StatusNotFound, gin.H{"error": "Missing consent challenge"})
    c.Abort()
    return
  }

  var authorizeRequest = cpbe.PostAuthorizationsAuthorizeRequest{
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

  authorizationsAuthorizeResponse, _ := cpbe.GetAuthorizationsAuthorize(consentChallenge)

  var consents = make(map[int]map[string]string)
  for index, name := range authorizationsAuthorizeResponse.RequestedScopes {
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

func postAuthorizeHandler(c *gin.Context) {
  var form authorizeForm
  c.Bind(&form)

  // comes from form post url
  challenge := c.Query("challenge")
  authorizeRequest := cpbe.PostAuthorizationsAuthorizeRequest{
    Challenge: challenge,
    GrantScopes: form.Consents,
  }

  authorizationsAuthorizeResponse, _ := cpbe.PostAuthorizationsAuthorize(authorizeRequest)

  fmt.Println(authorizationsAuthorizeResponse)

  if authorizationsAuthorizeResponse.Authorized {
    c.Redirect(302, authorizationsAuthorizeResponse.RedirectTo)
    c.Abort()
    return
  }

  c.JSON(200, gin.H{
    "authorized": false,
  })
}

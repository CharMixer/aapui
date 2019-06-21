package main

import (
  "github.com/gin-gonic/gin"
  "golang-cp-fe/config"
  "golang-cp-fe/interfaces"
  "golang-cp-fe/gateway/cpbe"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  "fmt"
)

type authorizeForm struct {
    Consents []string `form:"consents[]"`
}

func init() {
  config.InitConfigurations()
}

func main() {
    r := gin.Default()

    // Use CSRF on all our forms.
    fmt.Println("Using insecure CSRF for devlopment. Do not do this in production")
    adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.CPFe.CsrfAuthKey), csrf.Secure(false)))
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
  challenge := c.Query("consent_challenge")

  cpBeAuthorizationsAuthorizeResponse, _ := cpbe.GetAuthorizationsAuthorize(challenge)

  var consents = make(map[int]map[string]string)
  for index, name := range cpBeAuthorizationsAuthorizeResponse.RequestedScopes {
    // index is the index where we are
    // element is the element from someSlice for where we are
    consents[index] = map[string]string{
      "name": name,
    }
  }

  c.HTML(200, "authorize.html", gin.H{
    csrf.TemplateTag: csrf.TemplateField(c.Request),
    "requested_scopes": consents,
    "challenge": challenge,
  })
}

func postAuthorizeHandler(c *gin.Context) {
  var form authorizeForm
  c.Bind(&form)

  // comes from form post url
  challenge := c.Query("challenge")
  cpBePostAuthorizationsAuthorizeRequest := interfaces.CPBePostAuthorizationsAuthorizeRequest{
    Challenge: challenge,
    GrantScopes: form.Consents,
  }

  authorizeResponse, _ := cpbe.PostAuthorizationsAuthorize(cpBePostAuthorizationsAuthorizeRequest)

  fmt.Println(authorizeResponse)

  if authorizeResponse.Authorized {
    c.Redirect(302, authorizeResponse.RedirectTo)
    c.Abort()
    return
  }

  c.JSON(200, gin.H{
    "authorized": false,
  })
}

package controllers

import (
  //"fmt"
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"

  "golang-cp-fe/config"
  "golang-cp-fe/environment"
  "golang-cp-fe/gateway/cpbe"
)

type authorizeForm struct {
    Consents []string `form:"consents[]"`
    Accept string `form:"accept"`
    Cancel string `form:"cancel"`
}

func ShowAuthorization(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    requestId := c.MustGet(environment.RequestIdKey).(string)
    environment.DebugLog(route.LogId, "ShowAuthorization", "", requestId)

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

func SubmitAuthorization(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    requestId := c.MustGet(environment.RequestIdKey).(string)
    environment.DebugLog(route.LogId, "SubmitAuthorization", "", requestId)

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

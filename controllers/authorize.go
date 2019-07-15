package controllers

import (
  //"fmt"
  "strings"
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

    // NOTE: Requested more scopes of user than was previously granted to the app.
    var requestedScopes []string = authorizeResponse.RequestedScopes

    // Look for already granted consents for the id (sub) and app (client_id)
    consentRequest := cpbe.ConsentRequest{
      Subject: "wraix", // FIXME: find this from access token
      App: "Idp", // FIXME: Formalize this
    }
    grantedScopes, err := cpbe.FetchConsents(config.CpBe.AuthorizationsUrl, cpbeClient, consentRequest)
    if err != nil {
      environment.DebugLog(route.LogId, "ShowAuthorization", "Error: " + err.Error(), requestId)
      c.HTML(http.StatusInternalServerError, "authorize.html", gin.H{
        "error": err.Error(),
      })
    }

    d := Difference(requestedScopes, grantedScopes)
    if len(d) <= 0 {
      // Nothing to accept everything already accepted.
      environment.DebugLog(route.LogId, "ShowAuthorization", "Auto granted scopes: " + strings.Join(requestedScopes, ","), requestId)
      authorizeRequest := cpbe.AuthorizeRequest{
        Challenge: consentChallenge,
        GrantScopes: requestedScopes,
      }
      authorizationsAuthorizeResponse, _ := cpbe.Authorize(config.CpBe.AuthorizationsAuthorizeUrl, cpbeClient, authorizeRequest)
      if  authorizationsAuthorizeResponse.Authorized {
        c.Redirect(302, authorizationsAuthorizeResponse.RedirectTo)
        c.Abort()
        return
      } else {
        environment.DebugLog(route.LogId, "ShowAuthorization", "Auto granting scopes failed!", requestId)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to auto grant scopes."}) // FIXME: better error handling
        return
      }
    }

    var requestedConsents = make(map[int]map[string]string)
    for index, name := range d {
      // index is the index where we are
      // element is the element from someSlice for where we are
      requestedConsents[index] = map[string]string{
        "name": name,
      }
    }

    c.HTML(200, "authorize.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "requested_scopes": requestedConsents,
      "challenge": consentChallenge,
    })
  }
  return gin.HandlerFunc(fn)
}

// Set Difference: A - B
func Difference(a, b []string) (diff []string) {
  m := make(map[string]bool)

  for _, item := range b {
    m[item] = true
  }

  for _, item := range a {
    if _, ok := m[item]; !ok {
      diff = append(diff, item)
    }
  }
  return
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

      // FIXME: Update db model before asking hydra to accept consents. This way if db model update fails we can retry.

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

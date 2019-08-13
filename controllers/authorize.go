package controllers

import (
  "fmt"
  "strings"
  "net/http"

  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"

  "golang-cp-fe/config"
  "golang-cp-fe/environment"
  "golang-cp-fe/gateway/aapapi"
)

type authorizeForm struct {
    Consents []string `form:"consents[]"`
    Accept string `form:"accept"`
    Cancel string `form:"cancel"`
}

func ShowAuthorization(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "route.logid": route.LogId,
      "component": "aapui",
      "func": "ShowAuthorization",
    })
    log.Debug("Received authorization request");

    // comes from hydra redirect
    consentChallenge := c.Query("consent_challenge")
    if consentChallenge == "" {
      c.HTML(http.StatusNotFound, "authorize.html", gin.H{"error": "Missing consent challenge"})
      c.Abort()
      return
    }

    aapapiClient := aapapi.NewAapApiClient(env.AapApiConfig)

    var authorizeRequest = aapapi.AuthorizeRequest{
      Challenge: consentChallenge,
    }
    authorizeResponse, err := aapapi.Authorize(config.GetString("aapapi.public.url") + config.GetString("aapapi.public.endpoints.authorizationsAuthorize"), aapapiClient, authorizeRequest)
    if err != nil {
      c.HTML(http.StatusInternalServerError, "authorize.html", gin.H{
        "error": err.Error(),
      })
      c.Abort()
      return
    }

    if authorizeResponse.Authorized {
      log.Debug("Redirecting to " + authorizeResponse.RedirectTo)
      c.Redirect(http.StatusFound, authorizeResponse.RedirectTo)
      c.Abort()
      return
    }

    // NOTE: App requested more scopes of user than was previously granted to the app.
    var requestedScopes []string = authorizeResponse.RequestedScopes

    // Look for already granted consents for the id (sub) and app (client_id), so we can create the diffenence set and only present user with what is missing.
    consentRequest := aapapi.ConsentRequest{
      Subject: authorizeResponse.Subject,
      ClientId: authorizeResponse.ClientId,
      RequestedScopes: requestedScopes, // Only look for permissions that was requested (query optimization)
    }
    grantedScopes, err := aapapi.FetchConsents(config.GetString("aapapi.public.url") + config.GetString("aapapi.public.endpoints.authorizations"), aapapiClient, consentRequest)
    if err != nil {
      log.Debug(err.Error())
      c.HTML(http.StatusInternalServerError, "authorize.html", gin.H{
        "error": err.Error(),
      })
    }
    log.Debug("Granted scopes " + strings.Join(grantedScopes, ",") + " for client_id: "+ authorizeResponse.ClientId +" subject: " + authorizeResponse.Subject)

    diffScopes := Difference(requestedScopes, grantedScopes)

    log.Debug("FIXME: Create identity property which decides if auto consent should be triggered.");
    /*
    if len(diffScopes) <= 0 {
      // Nothing to accept everything already accepted.

      environment.DebugLog(route.LogId, "ShowAuthorization", "Auto granted scopes: " + strings.Join(requestedScopes, ","), requestId)
      authorizeRequest := aapapi.AuthorizeRequest{
        Challenge: consentChallenge,
        GrantScopes: requestedScopes,
      }
      authorizationsAuthorizeResponse, _ := aapapi.Authorize(config.GetString("aapApi.public.url") + config.GetString("aapApi.public.endpoints.authorizationsAuthorize"), aapapiClient, authorizeRequest)
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
    */

    var requestedConsents = make(map[int]map[string]string)
    for index, name := range diffScopes {
      requestedConsents[index] = map[string]string{
        "name": name,
      }
    }

    var grantedConsents = make(map[int]map[string]string)
    for index, name := range grantedScopes {
      grantedConsents[index] = map[string]string{
        "name": name,
      }
    }

    c.HTML(200, "authorize.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "name": authorizeResponse.Subject,
      "client_id": authorizeResponse.ClientId,
      "requested_scopes": requestedConsents,
      "granted_scopes": grantedConsents,
      "consent_challenge": consentChallenge,
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

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "route.logid": route.LogId,
      "component": "aapui",
      "func": "SubmitAuthorization",
    })
    log.Debug("Received authorization request");

    var form authorizeForm
    c.Bind(&form)

    consentChallenge := c.Query("consent_challenge")

    aapapiClient := aapapi.NewAapApiClient(env.AapApiConfig)

    if form.Accept != "" {

      consents := form.Consents

      // To prevent tampering we ask for the authorzation data again to get client_id, subject etc.
      var authorizeRequest = aapapi.AuthorizeRequest{
        Challenge: consentChallenge,
        // NOTE: Do not add GrantScopes here as it will grant them instead of reading data from the challenge.
      }
      authorizeResponse, err := aapapi.Authorize(config.GetString("aapapi.public.url") + config.GetString("aapapi.public.endpoints.authorizationsAuthorize"), aapapiClient, authorizeRequest)
      if err != nil {
        fmt.Println(err)
        c.HTML(http.StatusInternalServerError, "authorize.html", gin.H{
          "error": err.Error(),
        })
        c.Abort()
        return
      }

      revokedConsents := Difference(authorizeResponse.RequestedScopes, consents)

      log.Debug("Please remove App is no longer needed")

      // Grant the accepted scopes to the client in Aap
      consentRequest := aapapi.ConsentRequest{
        Subject: authorizeResponse.Subject,
        ClientId: authorizeResponse.ClientId,
        GrantedScopes: consents,
        RevokedScopes: revokedConsents,
        RequestedScopes: authorizeResponse.RequestedScopes, // Send what was requested just in case we need it.
      }
      consentResponse, err := aapapi.CreateConsents(config.GetString("aapapi.public.url") + config.GetString("aapapi.public.endpoints.authorizations"), aapapiClient, consentRequest)
      if err != nil {
        fmt.Println(err)
        // FIXME: Signal errors to the authorization controller using session flash messages.
        c.Redirect(302, "/authorize?consent_challenge=" + consentChallenge)
        c.Abort()
        return
      }
      fmt.Println(consentResponse)

      // Grant the accepted scopes to the client in Hydra
      authorizeRequest = aapapi.AuthorizeRequest{
        Challenge: consentChallenge,
        GrantScopes: consents,
      }
      authorizationsAuthorizeResponse, _ := aapapi.Authorize(config.GetString("aapapi.public.url") + config.GetString("aapapi.public.endpoints.authorizationsAuthorize"), aapapiClient, authorizeRequest)
      if  authorizationsAuthorizeResponse.Authorized {
        c.Redirect(302, authorizationsAuthorizeResponse.RedirectTo)
        c.Abort()
        return
      }
    }

    // Deny by default.
    rejectRequest := aapapi.RejectRequest{
      Challenge: consentChallenge,
    }
    rejectResponse, _ := aapapi.Reject(config.GetString("aapapi.public.url") + config.GetString("aapapi.public.endpoints.authorizationsReject"), aapapiClient, rejectRequest)
    c.Redirect(302, rejectResponse.RedirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

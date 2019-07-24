package controllers

import (
  "fmt"
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
      c.HTML(http.StatusNotFound, "authorize.html", gin.H{"error": "Missing consent challenge"})
      c.Abort()
      return
    }

    cpbeClient := cpbe.NewCpBeClient(env.CpBeConfig)

    var authorizeRequest = cpbe.AuthorizeRequest{
      Challenge: consentChallenge,
    }
    authorizeResponse, err := cpbe.Authorize(config.Discovery.AapApi.Public.Url + config.Discovery.AapApi.Public.Endpoints.AuthorizationsAuthorize, cpbeClient, authorizeRequest)
    if err != nil {
      c.HTML(http.StatusInternalServerError, "authorize.html", gin.H{
        "error": err.Error(),
      })
      c.Abort()
      return
    }

    if authorizeResponse.Authorized {
      environment.DebugLog(route.LogId, "ShowAuthorization", "Redirecting to " + authorizeResponse.RedirectTo, requestId)
      c.Redirect(http.StatusFound, authorizeResponse.RedirectTo)
      c.Abort()
      return
    }

    // NOTE: App requested more scopes of user than was previously granted to the app.
    var requestedScopes []string = authorizeResponse.RequestedScopes

    // Look for already granted consents for the id (sub) and app (client_id), so we can create the diffenence set and only present user with what is missing.
    consentRequest := cpbe.ConsentRequest{
      Subject: authorizeResponse.Subject,
      App: "idpui", // FIXME: Formalize this. Remeber an app could have more than one identity (client_id) if we wanted to segment access within the app
      ClientId: "idpui", //authorizeResponse.ClientId, // "idpui"
      RequestedScopes: requestedScopes, // Only look for permissions that was requested (query optimization)
    }
    grantedScopes, err := cpbe.FetchConsents(config.Discovery.AapApi.Public.Url + config.Discovery.AapApi.Public.Endpoints.Authorizations, cpbeClient, consentRequest)
    if err != nil {
      environment.DebugLog(route.LogId, "ShowAuthorization", "Error: " + err.Error(), requestId)
      c.HTML(http.StatusInternalServerError, "authorize.html", gin.H{
        "error": err.Error(),
      })
    }
    environment.DebugLog(route.LogId, "ShowAuthorization", "Granted scopes " + strings.Join(grantedScopes, ",") + " for app: idpui and subject: " + authorizeResponse.Subject, requestId)

    diffScopes := Difference(requestedScopes, grantedScopes)

    // FIXME: Create identity property which decides if auto consent should be triggered.
    /*
    if len(diffScopes) <= 0 {
      // Nothing to accept everything already accepted.

      environment.DebugLog(route.LogId, "ShowAuthorization", "Auto granted scopes: " + strings.Join(requestedScopes, ","), requestId)
      authorizeRequest := cpbe.AuthorizeRequest{
        Challenge: consentChallenge,
        GrantScopes: requestedScopes,
      }
      authorizationsAuthorizeResponse, _ := cpbe.Authorize(config.Discovery.AapApi.Public.Url + config.Discovery.AapApi.Public.Endpoints.AuthorizationsAuthorize, cpbeClient, authorizeRequest)
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
    requestId := c.MustGet(environment.RequestIdKey).(string)
    environment.DebugLog(route.LogId, "SubmitAuthorization", "", requestId)

    var form authorizeForm
    c.Bind(&form)

    consentChallenge := c.Query("consent_challenge")

    cpbeClient := cpbe.NewCpBeClient(env.CpBeConfig)

    if form.Accept != "" {

      consents := form.Consents

      // To prevent tampering we ask for the authorzation data again to get client_id, subject etc.
      var authorizeRequest = cpbe.AuthorizeRequest{
        Challenge: consentChallenge,
        // NOTE: Do not add GrantScopes here as it will grant them instead of reading data from the challenge.
      }
      authorizeResponse, err := cpbe.Authorize(config.Discovery.AapApi.Public.Url + config.Discovery.AapApi.Public.Endpoints.AuthorizationsAuthorize, cpbeClient, authorizeRequest)
      if err != nil {
        fmt.Println(err)
        c.HTML(http.StatusInternalServerError, "authorize.html", gin.H{
          "error": err.Error(),
        })
        c.Abort()
        return
      }

      revokedConsents := Difference(authorizeResponse.RequestedScopes, consents)

      // Grant the accepted scopes to the client in Aap
      consentRequest := cpbe.ConsentRequest{
        Subject: authorizeResponse.Subject,
        App: "idpui", // FIXME: Formalize this. Remeber an app could have more than one identity (client_id) if we wanted to segment access within the app
        ClientId: "idpui", //authorizeResponse.ClientId, // "idpui"
        GrantedScopes: consents,
        RevokedScopes: revokedConsents,
        RequestedScopes: authorizeResponse.RequestedScopes, // Send what was requested just in case we need it.
      }
      consentResponse, err := cpbe.CreateConsents(config.Discovery.AapApi.Public.Url + config.Discovery.AapApi.Public.Endpoints.Authorizations, cpbeClient, consentRequest)
      if err != nil {
        fmt.Println(err)
        // FIXME: Signal errors to the authorization controller using session flash messages.
        c.Redirect(302, "/authorize?consent_challenge=" + consentChallenge)
        c.Abort()
        return
      }
      fmt.Println(consentResponse)

      // Grant the accepted scopes to the client in Hydra
      authorizeRequest = cpbe.AuthorizeRequest{
        Challenge: consentChallenge,
        GrantScopes: consents,
      }
      authorizationsAuthorizeResponse, _ := cpbe.Authorize(config.Discovery.AapApi.Public.Url + config.Discovery.AapApi.Public.Endpoints.AuthorizationsAuthorize, cpbeClient, authorizeRequest)
      if  authorizationsAuthorizeResponse.Authorized {
        c.Redirect(302, authorizationsAuthorizeResponse.RedirectTo)
        c.Abort()
        return
      }
    }

    // Deny by default.
    rejectRequest := cpbe.RejectRequest{
      Challenge: consentChallenge,
    }
    rejectResponse, _ := cpbe.Reject(config.Discovery.AapApi.Public.Url + config.Discovery.AapApi.Public.Endpoints.AuthorizationsReject, cpbeClient, rejectRequest)
    c.Redirect(302, rejectResponse.RedirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

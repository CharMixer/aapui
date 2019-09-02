package controllers

import (
  "strings"
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"

  "github.com/charmixer/aapui/config"
  "github.com/charmixer/aapui/environment"
  "github.com/charmixer/aapui/gateway/aap"
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
      "func": "ShowAuthorization",
    })

    // comes from hydra redirect
    consentChallenge := c.Query("consent_challenge")
    if consentChallenge == "" {
      c.HTML(http.StatusNotFound, "authorize.html", gin.H{"error": "Missing consent challenge"})
      c.Abort()
      return
    }

    aapClient := aap.NewAapApiClient(env.AapApiConfig)

    var authorizeRequest = aap.AuthorizeRequest{
      Challenge: consentChallenge,
    }
    authorizeResponse, err := aap.Authorize(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizationsAuthorize"), aapClient, authorizeRequest)
    if err != nil {
      c.HTML(http.StatusInternalServerError, "authorize.html", gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if authorizeResponse.Authorized {
      log.WithFields(logrus.Fields{"redirect_to": authorizeResponse.RedirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, authorizeResponse.RedirectTo)
      c.Abort()
      return
    }

    // NOTE: App requested more scopes of user than was previously granted to the app.
    var requestedScopes []string = authorizeResponse.RequestedScopes

    // Look for already granted consents for the id (sub) and app (client_id), so we can create the diffenence set and only present user with what is missing.
    consentRequest := aap.ConsentRequest{
      Subject: authorizeResponse.Subject,
      ClientId: authorizeResponse.ClientId,
      RequestedAudiences: authorizeResponse.RequestedAudiences,
      RequestedScopes: requestedScopes, // Only look for permissions that was requested (query optimization)
    }
    grantedScopes, err := aap.FetchConsents(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizations"), aapClient, consentRequest)
    if err != nil {
      log.Debug(err.Error())
      c.HTML(http.StatusInternalServerError, "authorize.html", gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    strGrantedScopes := strings.Join(grantedScopes, ",")
    log.WithFields(logrus.Fields{
      "client_id": authorizeResponse.ClientId,
      "subject":  authorizeResponse.Subject,
      "scopes": strGrantedScopes,
    }).Debug("Found granted scopes")

    diffScopes := Difference(requestedScopes, grantedScopes)

    log.WithFields(logrus.Fields{"fixme": 1}).Debug("Create identity property which decides if auto consent should be triggered.");
    /*
    if len(diffScopes) <= 0 {
      // Nothing to accept everything already accepted.

      environment.DebugLog(route.LogId, "ShowAuthorization", "Auto granted scopes: " + strings.Join(requestedScopes, ","), requestId)
      authorizeRequest := aap.AuthorizeRequest{
        Challenge: consentChallenge,
        GrantScopes: requestedScopes,
      }
      authorizationsAuthorizeResponse, _ := aap.Authorize(config.GetString("aapApi.public.url") + config.GetString("aapApi.public.endpoints.authorizationsAuthorize"), aapClient, authorizeRequest)
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

    var requestedAudiences = make(map[int]map[string]string)
    for index, aud := range consentRequest.RequestedAudiences {
      requestedAudiences[index] = map[string]string{
        "aud": aud,
      }
    }

    c.HTML(200, "authorize.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "name": authorizeResponse.Subject,
      "client_id": authorizeResponse.ClientId,
      "requested_scopes": requestedConsents,
      "granted_scopes": grantedConsents,
      "requested_audiences": requestedAudiences,
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
      "func": "SubmitAuthorization",
    })

    var form authorizeForm
    c.Bind(&form)

    consentChallenge := c.Query("consent_challenge")

    aapClient := aap.NewAapApiClient(env.AapApiConfig)

    if form.Accept != "" {

      consents := form.Consents

      // To prevent tampering we ask for the authorzation data again to get client_id, subject etc.
      var authorizeRequest = aap.AuthorizeRequest{
        Challenge: consentChallenge,
        // NOTE: Do not add GrantScopes here as it will grant them instead of reading data from the challenge. (This is a masked Read call)
      }
      authorizeResponse, err := aap.Authorize(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizationsAuthorize"), aapClient, authorizeRequest)
      if err != nil {
        log.Debug(err.Error())
        c.HTML(http.StatusInternalServerError, "authorize.html", gin.H{"error": err.Error()})
        c.Abort()
        return
      }

      revokedConsents := Difference(authorizeResponse.RequestedScopes, consents)

      // Grant the accepted scopes to the client in Aap
      consentRequest := aap.ConsentRequest{
        Subject: authorizeResponse.Subject,
        ClientId: authorizeResponse.ClientId,
        GrantedScopes: consents,
        RevokedScopes: revokedConsents,
        RequestedScopes: authorizeResponse.RequestedScopes, // Send what was requested just in case we need it.
        RequestedAudiences: authorizeResponse.RequestedAudiences,
      }
      _ /* consentResponse */, err = aap.CreateConsents(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizations"), aapClient, consentRequest)
      if err != nil {
        log.Debug(err.Error())
        log.WithFields(logrus.Fields{"fixme": 1}).Debug("Signal errors to the authorization controller using session flash messages")
        c.Redirect(302, "/authorize?consent_challenge=" + consentChallenge)
        c.Abort()
        return
      }

      // Grant the accepted scopes to the client in Hydra
      authorizeRequest = aap.AuthorizeRequest{
        Challenge: consentChallenge,
        GrantScopes: consents,
      }
      authorizationsAuthorizeResponse, _ := aap.Authorize(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizationsAuthorize"), aapClient, authorizeRequest)
      if  authorizationsAuthorizeResponse.Authorized {
        c.Redirect(302, authorizationsAuthorizeResponse.RedirectTo)
        c.Abort()
        return
      }
    }

    // Deny by default.
    rejectRequest := aap.RejectRequest{
      Challenge: consentChallenge,
    }
    rejectResponse, _ := aap.Reject(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizationsReject"), aapClient, rejectRequest)
    c.Redirect(302, rejectResponse.RedirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

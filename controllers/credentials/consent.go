package credentials

import (
  "strings"
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"

  aap "github.com/charmixer/aap/client"

  "github.com/charmixer/aapui/app"
  "github.com/charmixer/aapui/config"

  // bulky "github.com/charmixer/bulky/client"
)

type authorizeForm struct {
  Challenge string `form:"challenge" binding:"required" validate:"required,notblank"`
  Consents []string `form:"consents[]"`
  Accept   string   `form:"accept"`
  Cancel   string   `form:"cancel"`
}

type UIConsent struct {
  Name string
  Key string
  Title string
  Description string
}

func ShowConsent(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowConsent",
    })

    consentChallenge := c.Query("consent_challenge") // Originates in oauth2 delegator redirect. (hydra)
    if consentChallenge == "" {
      log.Debug("Missing consent challenge")
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    aapClient := app.AapClientUsingClientCredentials(env, c)

    var authorizeRequest = aap.AuthorizeRequest{
      Challenge: consentChallenge,
    }
    _, authorizeResponse, err := aap.Authorize(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizationsAuthorize"), aapClient, authorizeRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
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
    _, grantedScopes, err := aap.FetchConsents(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizations"), aapClient, consentRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
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
      authorizationsAuthorizeResponse, _ := aap.Authorize(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizationsAuthorize"), aapClient, authorizeRequest)
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
    log.Debug(grantedScopes)

    var requestedConsents []UIConsent
    for _, name := range diffScopes {
      requestedConsents = append(requestedConsents, UIConsent{Name:name, Key:name, Title:"Test Scope", Description:"Et fint scope"})
    }

    var grantedConsents []UIConsent
    for _, name := range grantedScopes {
      grantedConsents = append(grantedConsents, UIConsent{Name: name, Key:name, Title:"Test Scope", Description:"Et fint scope"})
    }

    var requestedAudiences = make(map[int]map[string]string)
    for index, aud := range consentRequest.RequestedAudiences {
      requestedAudiences[index] = map[string]string{
        "aud": aud,
      }
    }

    c.HTML(200, "consent.html", gin.H{
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      "title": "Consent",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Consent Provider",
      "provideraction": "Consent to application access on your behalf",
      "challenge": consentChallenge,
      "consentUrl": config.GetString("aapui.public.endpoints.consent"),

      "id": authorizeResponse.Subject,
      "name": "Test Name", //authorizeResponse.SubjectName,

      "clientId": authorizeResponse.ClientId,
      "clientName": "Test Client", // authorizeResponse.ClientName,

      "requestedConsents": requestedConsents,
      "grantedConsents": grantedConsents,

      "requestedAudiences": requestedAudiences,
    })
    return
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

func SubmitConsent(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitConsent",
    })

    var form authorizeForm
    c.Bind(&form)

    consentChallenge := c.Query("consent_challenge")

    aapClient := app.AapClientUsingClientCredentials(env, c)

    if form.Accept != "" {

      consents := form.Consents

      // To prevent tampering we ask for the authorzation data again to get client_id, subject etc.
      var authorizeRequest = aap.AuthorizeRequest{
        Challenge: consentChallenge,
        // NOTE: Do not add GrantScopes here as it will grant them instead of reading data from the challenge. (This is a masked Read call)
      }
      _, authorizeResponse, err := aap.Authorize(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizationsAuthorize"), aapClient, authorizeRequest)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
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
      _, _ /* consentResponse */, err = aap.CreateConsents(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizations"), aapClient, consentRequest)
      if err != nil {
        log.Debug(err.Error())
        log.WithFields(logrus.Fields{"fixme": 1}).Debug("Signal errors to the authorization controller using session flash messages")
        c.Redirect(http.StatusFound, "/authorize?consent_challenge=" + consentChallenge)
        c.Abort()
        return
      }

      // Grant the accepted scopes to the client in Hydra
      authorizeRequest = aap.AuthorizeRequest{
        Challenge: consentChallenge,
        GrantScopes: consents,
      }
      _, authorizationsAuthorizeResponse, _ := aap.Authorize(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizationsAuthorize"), aapClient, authorizeRequest)
      if  authorizationsAuthorizeResponse.Authorized {
        c.Redirect(http.StatusFound, authorizationsAuthorizeResponse.RedirectTo)
        c.Abort()
        return
      }
    }

    // Deny by default.
    rejectRequest := aap.RejectRequest{
      Challenge: consentChallenge,
    }
    _, rejectResponse, _ := aap.Reject(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.authorizationsReject"), aapClient, rejectRequest)
    c.Redirect(http.StatusFound, rejectResponse.RedirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

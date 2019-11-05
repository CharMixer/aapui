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

  bulky "github.com/charmixer/bulky/client"
)

type authorizeForm struct {
  Challenge string `form:"challenge" binding:"required" validate:"required,notblank"`
  Consents []string `form:"consents[]"`
  Accept   string   `form:"accept"`
  Cancel   string   `form:"cancel"`
}

type UIConsent struct {
  aap.Publish
}

type PublisherScope struct {
  Publisher, Scope string
}

func ShowConsent(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowConsent",
    })

    consentChallenge := c.Query("consent_challenge") // Originates in oauth2 delegator redirect. (hydra)
    if consentChallenge == "" {
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    aapClient := app.AapClientUsingClientCredentials(env, c)

    var authorizeRequest = []aap.CreateConsentsAuthorizeRequest{ {Challenge: consentChallenge} }
    status, responses, err := aap.CreateConsentsAuthorize(aapClient, config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents.authorize"), authorizeRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if status == http.StatusOK {

      var authorization aap.CreateConsentsAuthorizeResponse
      status, restErr := bulky.Unmarshal(0, responses, &authorization)
      if len(restErr) > 0 {
        for _,e := range restErr {
          log.Debug("Rest error: " + e.Error)
        }
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if status == http.StatusOK {

        // Already authorized. This is skip in hydra. No questions asked.
        if authorization.Authorized {
          log.WithFields(logrus.Fields{ "redirect_to": authorization.RedirectTo }).Debug("Redirecting")
          c.Redirect(http.StatusFound, authorization.RedirectTo)
          c.Abort()
          return
        }

        // NOTE: App requested more scopes of user than was previously granted to the app according to hydra.

        var publisherIds []string = authorization.RequestedAudiences
        mapPublisherIds := make(map[string]bool)
        for _, publisherId := range publisherIds {
          mapPublisherIds[publisherId] = true
        }

        var requestedScopes []string = authorization.RequestedScopes
        var mapRequestedScopes map[string]bool = make(map[string]bool)
        for _, scope := range requestedScopes {
          mapRequestedScopes[scope] = true
        }

        // Fetch subscription scopes for the client (client is subscribed to published scopes, meaning the client is allowed to request access token for the published scopes)


        var readSubscriptionsRequests []aap.ReadSubscriptionsRequest

        for _, aud := range publisherIds {
          readSubscriptionsRequests = append(readSubscriptionsRequests, aap.ReadSubscriptionsRequest{ Subscriber:authorization.ClientId, Scopes: requestedScopes, Publisher: aud })
        }

        if len(readSubscriptionsRequests) <= 0 {
          readSubscriptionsRequests = append(readSubscriptionsRequests, aap.ReadSubscriptionsRequest{ Subscriber:authorization.ClientId, Scopes: requestedScopes })
        }

        status, responses, err = aap.ReadSubscriptions(aapClient, config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.subscriptions.collection"), readSubscriptionsRequests)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        if status != http.StatusOK {
          return
        }

        // should be bulky stuff
        var countSubscriptions = 0
        var mapPublisherScopes = make(map[string][]string)
        var mapConsents = make(map[PublisherScope]bool)
        for i,_ := range readSubscriptionsRequests {
          var subs aap.ReadSubscriptionsResponse
          status, restErr := bulky.Unmarshal(i, responses, &subs)
          if len(restErr) > 0 {
            for _,e := range restErr {
              log.Debug("Rest error: " + e.Error)
            }
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          if status == http.StatusOK {
            for _,s := range subs {
              mapPublisherScopes[s.Publisher] = append(mapPublisherScopes[s.Publisher], s.Scope)

              // initialize all consents with false - will be updated from GET /consents later
              mapConsents[PublisherScope{s.Publisher, s.Scope}] = false

              countSubscriptions = countSubscriptions + 1
            }
          }
        }

        if countSubscriptions <= 0 {
          log.WithFields(logrus.Fields{ "scopes":strings.Join(authorization.RequestedScopes, " ") }).Debug("Not allowed to request any scopes")
          c.AbortWithStatus(http.StatusForbidden)
          return
        }



        // Fetch publishings for the publisher (publisher published scopes) - needed to get title and description to render.

        var readPublishingsRequests []aap.ReadPublishesRequest

        for publisher, scopes := range mapPublisherScopes {
          readPublishingsRequests = append(readPublishingsRequests, aap.ReadPublishesRequest{Publisher: publisher, Scopes: scopes})
        }
        status, responses, err = aap.ReadPublishes(aapClient, config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.publishes"), readPublishingsRequests)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        if status != http.StatusOK {
          return
        }



        // should be bulky stuff
        mapPublishingsDefinitions := make(map[PublisherScope]aap.Publish)
        var countPublishings = 0
        for i,_ := range readPublishingsRequests {
          var publishings aap.ReadPublishesResponse
          status, restErr := bulky.Unmarshal(i, responses, &publishings)
          if len(restErr) > 0 {
            for _,e := range restErr {
              log.Debug("Rest error: " + e.Error)
            }
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          if status == http.StatusOK {
            for _,p := range publishings {
              mapPublishingsDefinitions[PublisherScope{p.Publisher, p.Scope}] = p
              countPublishings = countPublishings + 1
            }
          }
        }


        // Fetch consents for the subject to the subscriber (client). Did subject already consent to client requesting access tokens for the scopes on subject behalf.
        var readConsentsRequests []aap.ReadConsentsRequest
        for publisher, scopes := range mapPublisherScopes {
          readConsentsRequests = append(readConsentsRequests, aap.ReadConsentsRequest{
            Reference: authorization.Subject,
            Subscriber: authorization.ClientId,
            Publisher: publisher,
            Scopes: scopes,
          })
        }

        status, responses, err = aap.ReadConsents(aapClient, config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents.collection"), readConsentsRequests)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        if status != http.StatusOK {
          return
        }

        // should be bulky stuff
        for i,_ := range readConsentsRequests {
          var consents aap.ReadConsentsResponse
          status, restErr := bulky.Unmarshal(i, responses, &consents)
          if len(restErr) > 0 {
            for _,e := range restErr {
              log.Debug("Rest error: " + e.Error)
            }
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          if status == http.StatusOK {
            for _,c := range consents {
              mapConsents[PublisherScope{c.Publisher, c.Scope}] = true
            }
          }
        }




/*

        // Calculate difference set and only asked for consent to scopes that are not already granted.
        // Look for already consented scopes in consent model for request.
        var grantedScopes []string
        diffScopes := Difference(requestedScopes, grantedScopes)
        if len(diffScopes) <= 0 {
          // Nothing to accept everything already accepted.

          var authorizeRequest = []aap.CreateConsentsAuthorizeRequest{ {Challenge:consentChallenge, GrantScopes:requestedScopes} }
          status, responses, err := aap.CreateConsentsAuthorize(aapClient, config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents.authorize"), authorizeRequest)
          if err != nil {
            log.Debug(err.Error())
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          if status == http.StatusOK {

            var authorization aap.CreateConsentsAuthorizeResponse
            status, restErr := bulky.Unmarshal(0, responses, &authorization)
            if len(restErr) > 0 {
              for _,e := range restErr {
                log.Debug("Rest error: " + e.Error)
              }
              c.AbortWithStatus(http.StatusInternalServerError)
              return
            }

            if status == http.StatusOK {

              if authorization.Authorized {
                log.WithFields(logrus.Fields{ "redirect_to": authorization.RedirectTo }).Debug("Redirecting")
                c.Redirect(http.StatusFound, authorization.RedirectTo)
                c.Abort()
                return
              }

            }

          }

          // Deny by default
          log.WithFields(logrus.Fields{ "challenge":consentChallenge }).Debug("Accept consent challenge failed")
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }
*/

        var requestedConsents map[string][]UIConsent = make(map[string][]UIConsent) // Requested scopes grouped by audience
        var grantedConsents map[string][]UIConsent = make(map[string][]UIConsent) // Granted scopes grouped by audience

        for publisherScope, consented := range mapConsents {

          publisher := publisherScope.Publisher
          publishDefinition := mapPublishingsDefinitions[publisherScope]

          if consented == true {
            grantedConsents[publisher] = append(grantedConsents[publisher], UIConsent{ publishDefinition })
            continue
          }

          // deny by default
          requestedConsents[publisher] = append(requestedConsents[publisher], UIConsent{ publishDefinition })
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

          "id":    authorization.Subject,
          "name":  authorization.SubjectName,
          "email": authorization.SubjectEmail,

          "clientId":   authorization.ClientId,
          "clientName": authorization.ClientName,

          "requestedConsents": requestedConsents,
          "grantedConsents":   grantedConsents,

        })
        return
      }

    }

    // Deny by default
    log.Debug(responses)
    c.AbortWithStatus(http.StatusForbidden)
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
/*
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
      _, authorizeResponse, err := aap.Authorize(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents.authorize"), aapClient, authorizeRequest)
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
      _, _, err = aap.CreateConsents(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents"), aapClient, consentRequest)
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
      _, authorizeResponse, _ := aap.Authorize(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents.authorize"), aapClient, authorizeRequest)
      if  authorizeResponse.Authorized {
        c.Redirect(http.StatusFound, authorizeResponse.RedirectTo)
        c.Abort()
        return
      }
    }

    // Deny by default.
    rejectRequest := aap.RejectRequest{
      Challenge: consentChallenge,
    }
    _, rejectResponse, _ := aap.Reject(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents.reject"), aapClient, rejectRequest)
    c.Redirect(http.StatusFound, rejectResponse.RedirectTo)
    c.Abort()
    */
  }
  return gin.HandlerFunc(fn)
}

package credentials

import (
  "sort"
  "net/http"
  "net/url"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/go-playground/form"

  aap "github.com/charmixer/aap/client"

  "github.com/charmixer/aapui/app"
  "github.com/charmixer/aapui/config"
  "github.com/charmixer/aapui/utils"

  bulky "github.com/charmixer/bulky/client"
)

type authorizeForm struct {
  Challenge string
  Accept string
  Cancel string
  Consents []struct {
    Audience string
    Scope string
    Consented bool
  }
}

type UIConsent struct {
  aap.ConsentRequest
}

type AudienceScope struct {
  Audience, Scope string
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

    var authorizeRequest = []aap.ReadConsentsAuthorizeRequest{ {Challenge: consentChallenge} }
    status, responses, err := aap.ReadConsentsAuthorize(aapClient, config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents.authorize"), authorizeRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if status == http.StatusOK {

      var authorization aap.ReadConsentsAuthorizeResponse
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

        var requestedConsents []UIConsent
        var grantedConsents []UIConsent

        for _, cr := range authorization.ConsentRequests {

          if cr.Consented == true {
            grantedConsents = append(grantedConsents, UIConsent{ cr })
            continue
          }

          // deny by default
          requestedConsents = append(requestedConsents, UIConsent{ cr })
        }

        // Sort by audience, title
        sort.Slice(requestedConsents, func(i, j int) bool {
          if requestedConsents[i].Audience < requestedConsents[j].Audience {
              return true
          }
          if requestedConsents[i].Audience > requestedConsents[j].Audience {
              return false
          }
          return requestedConsents[i].Title < requestedConsents[j].Title
        })

        sort.Slice(grantedConsents, func(i, j int) bool {
          if grantedConsents[i].Audience < grantedConsents[j].Audience {
              return true
          }
          if grantedConsents[i].Audience > grantedConsents[j].Audience {
              return false
          }
          return grantedConsents[i].Title < grantedConsents[j].Title
        })

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

func SubmitConsent(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitConsent",
    })

    var decoder *form.Decoder = form.NewDecoder()

    var form authorizeForm
    c.Request.ParseForm()

    err := decoder.Decode(&form, c.Request.Form)
    if err != nil {
      log.Panic(err)
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }

    // Fetch the url that the submit happen to, so we can redirect back to it.
    q := url.Values{}
    q.Add("consent_challenge", form.Challenge)
    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, &q)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    aapClient := app.AapClientUsingClientCredentials(env, c)

    if form.Cancel != "" {

      // Subject rejected the challenge.
      var rejectRequests = []aap.CreateConsentsRejectRequest{ {Challenge: form.Challenge} }
      status, responses, err := aap.CreateConsentsReject(aapClient, config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents.reject"), rejectRequests)
      if err != nil {
       log.Debug(err.Error())
       c.AbortWithStatus(http.StatusInternalServerError)
       return
      }

      if status != http.StatusOK {
       log.WithFields(logrus.Fields{ "challenge":form.Challenge, "status":status }).Debug("Request failed")
       c.AbortWithStatus(http.StatusInternalServerError)
       return
      }

      var authorization aap.CreateConsentsRejectResponse
      status, restErr := bulky.Unmarshal(0, responses, &authorization)
      if len(restErr) > 0 {
        for _,e := range restErr {
          log.Debug("Rest error: " + e.Error)
        }
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if status == http.StatusOK {
        // Rejected, successfully
        log.WithFields(logrus.Fields{ "redirect_to": authorization.RedirectTo }).Debug("Redirecting")
        c.Redirect(http.StatusFound, authorization.RedirectTo)
        c.Abort()
        return
      }

      // Deny by default, reject
      log.WithFields(logrus.Fields{ "challenge":form.Challenge, "status":status }).Debug("Reject failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if form.Accept != "" {

      // To prevent tampering read data from challenge
      var authorizeRequest = []aap.ReadConsentsAuthorizeRequest{ {Challenge: form.Challenge} }
      status, responses, err := aap.ReadConsentsAuthorize(aapClient, config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents.authorize"), authorizeRequest)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if status == http.StatusOK {

        var authorization aap.ReadConsentsAuthorizeResponse
        status, restErr := bulky.Unmarshal(0, responses, &authorization)
        if len(restErr) > 0 {
          for _,e := range restErr {
            log.Debug("Rest error: " + e.Error)
          }
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        if status == http.StatusOK {

          // Sanity check input data using this map.
          mapConsentableConsentRequests := make(map[AudienceScope]aap.ConsentRequest)
          for _, cr := range authorization.ConsentRequests {
            mapConsentableConsentRequests[AudienceScope{cr.Audience, cr.Scope}] = cr
          }

          var consentRequests []aap.CreateConsentsRequest
          for _, consent := range form.Consents {
            if consent.Consented == true {
              cr := mapConsentableConsentRequests[AudienceScope{consent.Audience, consent.Scope}]
              if cr != (aap.ConsentRequest{}) && cr.Consented == false {
                consentRequests = append(consentRequests, aap.CreateConsentsRequest{
                  Reference: authorization.Subject,
                  Subscriber: authorization.ClientId,
                  Publisher: cr.Audience,
                  Scope: cr.Scope,
                })
              }
            }
          }

          if len(consentRequests) > 0 {

            // Update consent model
            status, _, err = aap.CreateConsents(aapClient, config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.consents.collection"), consentRequests)
            if err != nil {
              log.Debug(err.Error())
              c.AbortWithStatus(http.StatusInternalServerError)
              return
            }

            if status == http.StatusOK {

              // Update hydra model
              var authorizeRequest = []aap.CreateConsentsAuthorizeRequest{ {Challenge: form.Challenge} }
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

                  // Accept success redirect
                  if authorization.Authorized == true {
                    log.WithFields(logrus.Fields{ "redirect_to": authorization.RedirectTo }).Debug("Redirecting")
                    c.Redirect(http.StatusFound, authorization.RedirectTo)
                    c.Abort()
                    return
                  }

                }

              }

            }

          }

        }

      }

    }

    // Deny by default. (redirect back to controller with errors)
    log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
    c.Redirect(http.StatusFound, submitUrl)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

package controllers

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"

  bulky "github.com/charmixer/bulky/client"

  aap "github.com/charmixer/aap/client"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/aapui/config"
  "github.com/charmixer/aapui/environment"
)

type grantsForm struct {
  Scope         string `form:"scope" binding:"required"`
  PublisherId   string `form:"publisher_id" binding:"required"`
  GrantedId     string `form:"granted_id" binding:"required"`
  DateStart     string `form:"date_start" binding:"required"`
  DateEnd       string `form:"date_end" binding:"required"`
}

func ShowGrants(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowAccess",
    })

    session := sessions.Default(c)

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "grants.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    aapClient := aap.NewAapClientWithUserAccessToken(env.HydraConfig, accessToken)
    idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

    // fetch grants

    url := config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.grants")
    _, responses, err := aap.ReadGrants(aapClient, url, []aap.ReadGrantsRequest{
      {Scope: "openid", Publisher:"74ac5-4a3f-441f-9ed9-b8e3e9b1f13c"},
    })

    if err != nil {
      c.AbortWithStatus(404)
      log.Debug(err.Error())
      return
    }

    var grants aap.ReadGrantsResponse
    _, restErr := bulky.Unmarshal(0, responses, &grants)
    if len(restErr) > 0 {
      for _,e := range restErr {
        // TODO show user somehow
        log.Debug("Rest error: " + e.Error)
      }

      c.AbortWithStatus(404)
      return
    }

    // fetch resourceservers

    url = config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.resourceservers.collection")
    _, responses, err = idp.ReadResourceServers(idpClient, url, nil)

    if err != nil {
      c.AbortWithStatus(404)
      log.Debug(err.Error())
      return
    }

    var resourceservers idp.ReadResourceServersResponse
    _, restErr = bulky.Unmarshal(0, responses, &resourceservers)
    if len(restErr) > 0 {
      for _,e := range restErr {
        // TODO show user somehow
        log.Debug("Rest error: " + e.Error)
      }

      c.AbortWithStatus(404)
      return
    }
    // fetch scopes

    url = config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.scopes")
    _, responses, err = aap.ReadScopes(aapClient, url, nil)

    if err != nil {
      c.AbortWithStatus(404)
      log.Debug(err.Error())
      return
    }

    var scopes aap.ReadScopesResponse
    _, restErr = bulky.Unmarshal(0, responses, &scopes)
    if len(restErr) > 0 {
      log.Debug(restErr)
      for _,e := range restErr {
        // TODO show user somehow
        log.Debug("Rest error: " + e.Error)
      }

      c.AbortWithStatus(404)
      return
    }

    c.HTML(200, "grants.html", gin.H{
      "title": "Grants",
      "grants": grants,
      "scopes": scopes,
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
      "idpUiUrl": config.GetString("idpui.public.url"),
      "aapUiUrl": config.GetString("aapui.public.url"),
    })

  }
  return gin.HandlerFunc(fn)
}

func SubmitGrants(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowAccess",
    })

    var form []grantsForm
    err := c.Bind(&form)
    if err != nil {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    test := c.PostFormArray("grants")
    c.AbortWithStatusJSON(http.StatusOK, test)
    return

    session := sessions.Default(c)

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "grants.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    aapClient := aap.NewAapClientWithUserAccessToken(env.HydraConfig, accessToken)

    url := config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.grants")

    idprs := "5cd0189d-d066-403d-b362-3554f6f7ec71"
    aaprs := "2e3c2c8e-1c94-4531-8978-a0f8c3cec44e"

    status, responses, err := aap.CreateGrants(aapClient, url, []aap.CreateGrantsRequest{
      {Scope:"openid", Publisher: idprs},
      {Scope:"offline", Publisher: idprs},
      {Scope:"logout:identity", Publisher: idprs},
      {Scope:"recover:identity", Publisher: idprs},

      {Scope:"openid", Publisher: aaprs},
      {Scope:"offline", Publisher: aaprs},
    })

    if err != nil {
      c.AbortWithStatus(404)
      log.Debug(err.Error())
      return
    }

    if status == 200 {
      var scopes aap.ReadScopesResponse
      _, restErr := bulky.Unmarshal(0, responses, &scopes)
      if restErr != nil {
        for _,e := range restErr {
          // TODO show user somehow
          log.Debug("Rest error: " + e.Error)
        }
      }

      c.HTML(200, "grants.html", gin.H{
        "title": "Grants",
        "scopes": scopes,
        csrf.TemplateTag: csrf.TemplateField(c.Request),
        "links": []map[string]string{
          {"href": "/public/css/dashboard.css"},
        },
        "idpUiUrl": config.GetString("idpui.public.url"),
        "aapUiUrl": config.GetString("aapui.public.url"),
      })
    }

    c.AbortWithStatus(404)
  }
  return gin.HandlerFunc(fn)
}

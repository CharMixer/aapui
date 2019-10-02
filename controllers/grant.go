package controllers

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"

  aap "github.com/charmixer/aap/client"

  "github.com/charmixer/aapui/config"
  "github.com/charmixer/aapui/environment"
)

type grantsForm struct {
  Scope         string `form:"scope" binding:"required"`
  PublisherId   string `form:"publisher_id" binding:"required"`
  GrantedId     string `form:"granted_id" binding:"required"`
  GranterId     string `form:"granter_id" binding:"required"`
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

    url := config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.grants")

    idprs := "1b8761b4-876e-4e5e-aaea-a756ef4520a2"
    aaprs := "39a04c64-9f33-4062-bb74-90ec8d05346c"

    status, createGrantsResponse, err := aap.CreateGrants(url, aapClient, []aap.CreateGrantsRequest{
      {Scope:"openid", PublishedBy: idprs},
      {Scope:"offline", PublishedBy: idprs},
      {Scope:"logout:identity", PublishedBy: idprs},
      {Scope:"recover:identity", PublishedBy: idprs},

      {Scope:"openid", PublishedBy: aaprs},
      {Scope:"offline", PublishedBy: aaprs},
    })

    if err != nil {
      c.AbortWithStatus(404)
      log.Debug(err.Error())
      return
    }

    if status == 200 {
      _, ok, restErr := aap.UnmarshalResponse(0, createGrantsResponse)
      if restErr != nil {
        for _,e := range restErr {
          // TODO show user somehow
          log.Debug("Rest error: " + e.Error)
        }
      }

      c.HTML(200, "grants.html", gin.H{
        "title": "Grants",
        "scopes": ok,
        csrf.TemplateTag: csrf.TemplateField(c.Request),
        "links": []map[string]string{
          {"href": "/public/css/dashboard.css"},
        },
      })
    }


    //url := config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.grants")
    //status, readGrantsResponse, err := aap.ReadGrants(url, aapClient, nil)

    //if err != nil {
      //c.AbortWithStatus(404)
      //log.Debug(err.Error())
      //return
    //}

    //if status == 200 {
      //_, ok, restErr := aap.UnmarshalResponse(0, readGrantsResponse)
      //if restErr != nil {
        //for _,e := range restErr {
          //// TODO show user somehow
          //log.Debug("Rest error: " + e.Error)
        //}
      //}

      //c.HTML(200, "grants.html", gin.H{
        //"title": "Grants",
        //"scopes": ok,
        //csrf.TemplateTag: csrf.TemplateField(c.Request),
        //"links": []map[string]string{
          //{"href": "/public/css/dashboard.css"},
        //},
      //})
    //}

    c.AbortWithStatus(404)
  }
  return gin.HandlerFunc(fn)
}

func SubmitGrants(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowAccess",
    })

    var form newAccessForm
    err := c.Bind(&form)
    if err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "access_new.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    aapClient := aap.NewAapClientWithUserAccessToken(env.HydraConfig, accessToken)

    var createScopesRequests []aap.CreateScopesRequest
    createScopesRequests = append(createScopesRequests, aap.CreateScopesRequest{
      Scope:               form.Scope,
      Title:               form.Title,
      Description:         form.Description,
    })

    url := config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.scopes")

    _, createdScopesResponse, err := aap.CreateScopes(url, aapClient, createScopesRequests)
    _, _, restErr := aap.UnmarshalResponse(0, createdScopesResponse)

    if restErr != nil {
      c.HTML(http.StatusOK, "access_new.html", gin.H{
        "title": "Create new access right",
        "errors": restErr,
        "links": []map[string]string{
          {"href": "/public/css/dashboard.css"},
        },
      })
      c.Abort()
      return
    }

    c.Redirect(http.StatusFound, "/access")
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

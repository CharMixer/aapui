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

type newAccessForm struct {
  Scope       string `form:"scope" binding:"required"`
  Title       string `form:"title" binding:"required"`
  Description string `form:"description" binding:"required"`
}

func ShowAccess(env *environment.State, route environment.Route) gin.HandlerFunc {
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
      c.HTML(http.StatusNotFound, "access_new.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    aapClient := aap.NewAapClientWithUserAccessToken(env.HydraConfig, accessToken)

    url := config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.scopes")
    readScopesResponse, _ := aap.ReadScopes(url, aapClient, nil)
    //readScopesResponse, _ := aap.ReadScopes(url, aapClient, []aap.ReadScopesRequest{{Scope: ""},{Scope: "openid"}})

    _, ok, restErr := aap.UnmarshalResponse(0, readScopesResponse)
    if restErr != nil {
      for _,e := range restErr {
        // TODO show user somehow
        log.Println("Rest error: " + e.Error)
      }
    }

    c.HTML(200, "access.html", gin.H{
      "title": "Access",
      "scopes": ok,
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
    })
  }
  return gin.HandlerFunc(fn)
}


func ShowAccessNew(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowAccessNew",
    })

    c.HTML(200, "access_new.html", gin.H{
      "title": "Create new access right",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitAccessNew(env *environment.State, route environment.Route) gin.HandlerFunc {
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

    createdScopesResponse, err := aap.CreateScopes(url, aapClient, createScopesRequests)
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

    c.Redirect(http.StatusMovedPermanently, "/access")
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

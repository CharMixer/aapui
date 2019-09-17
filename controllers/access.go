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

    var readScopesRequests []aap.ReadScopesRequest
    readScopesRequests = append(readScopesRequests, aap.ReadScopesRequest{})

    url := config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.scopes")
    readScopesResponse, _ := aap.ReadScopes(url, aapClient, readScopesRequests)
    log.Println(readScopesResponse)

    c.HTML(200, "access.html", gin.H{
      "title": "Access",
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

    var createScopesRequest = aap.CreateScopesRequest{
      Scope:               form.Scope,
      Title:               form.Title,
      Description:         form.Description,
      //CreatedByIdentityId: idToken.Subject,
    }

    url := config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.scopes")

    createdScopeResponse, err := aap.CreateScopes(url, aapClient, createScopesRequest)
    log.Println(createdScopeResponse)

    if err != nil {
      log.Println("Failed to call POST " + url)
      log.Println(err)

      c.HTML(http.StatusInternalServerError, "access_new.html", gin.H{
        "error": err.Error(),
        "links": []map[string]string{
          {"href": "/public/css/dashboard.css"},
        },
      })
      c.Abort()
      return
    }

    log.Println("Successfully called POST " + url)

    c.Redirect(http.StatusMovedPermanently, "/access")
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

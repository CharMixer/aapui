package controllers

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"

  aap "github.com/charmixer/aap/client"

  "github.com/charmixer/aapui/config"
  "github.com/charmixer/aapui/environment"
)

type NewAccessForm struct {
  Scope string `form:"scope" binding:"required"`
  Title string `form:"title" binding:"required"`
  Description string `form:"description" binding:"required"`
}

func ShowAccess(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowAccess",
    })

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

    var form NewAccessForm
    c.Bind(&form)

    aapClient := aap.NewAapClient(env.AapApiConfig)

    var createScopesRequest = aap.CreateScopesRequest{
      Scope: form.Scope,
      Title: form.Title,
      Description: form.Description,
      CreatedByIdentityId: "34be04a8-6c73-48af-be48-b6cf4b4cdcb3",
    }

    url := config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.scopes")

    _, err := aap.CreateScopes(url, aapClient, createScopesRequest)

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

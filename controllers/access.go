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

func ShowAccess(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowAccess",
    })

    aapClient := aap.NewAapClient(env.AapApiConfig)

    var createAccessRequest = aap.CreateAccessRequest{
      Scope: "some:scope:name",
      Title: "Some scope name",
    }
    createAccessResponse, err := aap.CreateAccess(config.GetString("aap.public.url") + config.GetString("aap.public.endpoints.access"), aapClient, createAccessRequest)
    if err != nil {
      log.Println("Failed to call POST /access")

      c.HTML(http.StatusInternalServerError, "access.html", gin.H{
        "error": err.Error(),
        "links": []map[string]string{
          {"href": "/public/css/dashboard.css"},
        },
      })
      c.Abort()
      return
    }

    log.Println(createAccessResponse, "Called POST /access")

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

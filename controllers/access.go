package controllers

import (
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"

  "github.com/charmixer/aapui/environment"
)

func ShowAccess(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowAccess",
    })

    c.HTML(200, "permissions.html", gin.H{
      "title": "Permissions",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
    })
  }
  return gin.HandlerFunc(fn)
}

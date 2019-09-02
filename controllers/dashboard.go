package controllers

import (
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "aapui/environment"
)

func ShowDashboard(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowDashboard",
    })

    c.HTML(200, "dashboard.html", gin.H{
      "title": "Dashboard",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
    })
  }
  return gin.HandlerFunc(fn)
}

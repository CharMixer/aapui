package main

import (
    "github.com/gin-gonic/gin"
)

type authorizeForm struct {
    Consents []string `form:"consents[]"`
}

func main() {
    r := gin.Default()

    r.Static("/public", "public")

    r.LoadHTMLGlob("views/*")

    r.GET("/", getAuthorizeHandler)
    r.GET("/authorize", getAuthorizeHandler)
    r.POST("/authorize", postAuthorizeHandler)

    r.Run() // defaults to :8080, uses env PORT if set
}

func getAuthorizeHandler(c *gin.Context) {
    c.HTML(200, "authorize.html", nil)
}

func postAuthorizeHandler(c *gin.Context) {
    var form authorizeForm
    c.Bind(&form)
    c.JSON(200, gin.H{
        "consents": form.Consents })
}

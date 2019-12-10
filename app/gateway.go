package app

import (
  "github.com/gin-gonic/gin"
  aap "github.com/opensentry/aap/client"
)

func AapClientUsingClientCredentials(env *Environment, c *gin.Context) (*aap.AapClient) {
  return aap.NewAapClient(env.AapConfig)
}

package environment

import (
  "golang.org/x/oauth2/clientcredentials"
  oidc "github.com/coreos/go-oidc"
)

const (
  RequestIdKey string = "RequestId"
  AccessTokenKey string = "access_token"
  IdTokenKey string = "id_token"
  LogKey string = "log"
)

type State struct {  
  Provider *oidc.Provider
  AapApiConfig *clientcredentials.Config
}

type Route struct {
  URL string
  LogId string
}

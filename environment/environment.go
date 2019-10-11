package environment

import (
  "golang.org/x/oauth2/clientcredentials"
  oidc "github.com/coreos/go-oidc"
  "golang.org/x/oauth2"
)

const (
  RequestIdKey string = "RequestId"
  AccessTokenKey string = "access_token"
  IdTokenKey string = "id_token"
  LogKey string = "log"
  SessionStoreKey string = "aapui"
  SessionStateKey string = "state"
  SessionTokenKey string = "token"
  SessionIdTokenKey string = "idtoken"
)

type State struct {
  Provider *oidc.Provider
  AapApiConfig *clientcredentials.Config
  IdpApiConfig *clientcredentials.Config
  HydraConfig *oauth2.Config
}

type Route struct {
  URL string
  LogId string
}

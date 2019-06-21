package config

import (
  "os"
  "strings"
)

type HydraConfig struct {
  Url                           string
  AdminUrl                      string
}

type ConsentBackendConfig struct {
  Url                           string
  AuthorizationsUrl             string
  AuthorizationsAuthorizeUrl    string
}

type ConsentFrontendConfig struct {
  CsrfAuthKey string
}

type OAuth2ClientConfig struct {
  ClientId        string
  ClientSecret    string
  Scopes          []string
  RedirectURL     string
  Endpoint        string
}

var Hydra HydraConfig
var CPBe ConsentBackendConfig
var CPFe ConsentFrontendConfig
var OAuth2Client OAuth2ClientConfig

func InitConfigurations() {
  Hydra.Url                             = getEnvStrict("HYDRA_URL")
  Hydra.AdminUrl                        = getEnvStrict("HYDRA_ADMIN_URL")

  CPBe.Url                              = getEnvStrict("CP_BACKEND_URL")
  CPBe.AuthorizationsUrl                = CPBe.Url + "/v1/authorizations"
  CPBe.AuthorizationsAuthorizeUrl       = CPBe.AuthorizationsUrl + "/authorize"

  CPFe.CsrfAuthKey                      = getEnv("CP_FRONTEND_CSRF_AUTH_KEY")

  OAuth2Client.ClientId                 = getEnv("OAUTH2_CLIENT_CLIENT_ID")
  OAuth2Client.ClientSecret             = getEnv("OAUTH2_CLIENT_ClIENT_SECRET")
  OAuth2Client.Scopes                   = strings.Split(getEnv("OAUTH2_CLIENT_SCOPES"), ",")
  OAuth2Client.RedirectURL              = getEnv("OAUTH2_CLIENT_REDIRECT_URL")
  OAuth2Client.Endpoint                 = getEnv("OAUTH2_CLIENT_ENDPOINT")
}

func getEnv(name string) string {
  return os.Getenv(name)
}

func getEnvStrict(name string) string {
  r := getEnv(name)

  if r == "" {
    panic("Missing environment variable: " + name)
  }

  return r
}

package config

import (
  "os"
)

type HydraConfig struct {
  Url             string
  AdminUrl        string
  AuthenticateUrl string
  TokenUrl        string
  UserInfoUrl     string
  PublicUrl             string
  PublicAuthenticateUrl string
  PublicTokenUrl        string
  PublicLogoutUrl       string
  PublicUserInfoUrl     string
}

type ConsentBackendConfig struct {
  Url                           string
  AuthorizationsUrl             string
  AuthorizationsAuthorizeUrl    string
  AuthorizationsRejectUrl       string
}

type ConsentFrontendConfig struct {
  CsrfAuthKey string
  ClientId                      string
  ClientSecret                  string
  RequiredScopes                []string
}

type OAuth2ClientConfig struct {
  ClientId        string
  ClientSecret    string
  Scopes          []string
  RedirectURL     string
  Endpoint        string
}

var Hydra HydraConfig
var CpBe ConsentBackendConfig
var CpFe ConsentFrontendConfig

func InitConfigurations() {
  Hydra.Url                   = getEnvStrict("HYDRA_URL")
  Hydra.AdminUrl              = getEnvStrict("HYDRA_ADMIN_URL")
  Hydra.AuthenticateUrl       = Hydra.Url + "/oauth2/auth"
  Hydra.TokenUrl              = Hydra.Url + "/oauth2/token"
  Hydra.UserInfoUrl           = Hydra.Url + "/userinfo"

  Hydra.PublicUrl             = getEnvStrict("HYDRA_PUBLIC_URL")
  Hydra.PublicLogoutUrl       = Hydra.PublicUrl + "/oauth2/sessions/logout"
  Hydra.PublicAuthenticateUrl = Hydra.PublicUrl + "/oauth2/auth"
  Hydra.PublicTokenUrl        = Hydra.PublicUrl + "/oauth2/token"
  Hydra.PublicUserInfoUrl     = Hydra.PublicUrl + "/userinfo"

  CpBe.Url                              = getEnvStrict("CP_BACKEND_URL")
  CpBe.AuthorizationsUrl                = CpBe.Url + "/authorizations"
  CpBe.AuthorizationsAuthorizeUrl       = CpBe.AuthorizationsUrl + "/authorize"
  CpBe.AuthorizationsRejectUrl       = CpBe.AuthorizationsUrl + "/reject"

  CpFe.CsrfAuthKey                      = getEnvStrict("CP_FRONTEND_CSRF_AUTH_KEY")
  CpFe.ClientId                         = getEnvStrict("CP_FRONTEND_OAUTH2_CLIENT_ID")
  CpFe.ClientSecret                     = getEnvStrict("CP_FRONTEND_OAUTH2_CLIENT_SECRET")
  CpFe.RequiredScopes                   = []string{"openid", "cpbe.authorize"}
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

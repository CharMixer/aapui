package config

import (
  "os"
  "github.com/spf13/viper"
  "fmt"
  "strings"
)

type SelfConfig struct {
  Url             string
  Port            string
  CsrfAuthKey     string
  ClientId        string
  ClientSecret    string
  RequiredScopes  []string
}


type HydraConfig struct {
  Url             string
  AdminUrl        string
  AuthenticateUrl string
  TokenUrl        string
  UserInfoUrl     string
  LogoutUrl       string
}

type ConsentBackendConfig struct {
  Url                           string
  AuthorizationsUrl             string
  AuthorizationsAuthorizeUrl    string
  AuthorizationsRejectUrl       string
}

type OAuth2ClientConfig struct {
  ClientId        string
  ClientSecret    string
  Scopes          []string
  RedirectURL     string
  Endpoint        string
}

type DiscoveryConfig struct {
  IdpUi struct {
    Public struct {
      Url  string
      Port int
      Endpoints struct {
      }
    }
  }
  IdpApi struct {
    Public struct {
      Url  string
      Port int
      Endpoints struct {
      }
    }
  }
  AapUi struct {
    Public struct {
      Url  string
      Port int
      Endpoints struct {
      }
    }
  }
  AapApi struct {
    Public struct {
      Url  string
      Port int
      Endpoints struct {
        Authorizations string
        AuthorizationsAuthorize string
        AuthorizationsReject string
      }
    }
  }
  Hydra struct {
    Public struct {
      Url  string
      Port int
      Endpoints struct {
        HealthAlive string
        HealthReady string
      }
    }
    Private struct {
      Url  string
      Port int
    }
  }
}

type AppConfig struct {

}

var Discovery DiscoveryConfig
var App AppConfig



var Hydra HydraConfig
var CpBe ConsentBackendConfig
var Self SelfConfig

func setDefaults() {
  viper.SetDefault("config.discovery.path", "./discovery.yml")
  viper.SetDefault("config.app.path", "./app.yml")
}

func InitConfigurations() {
  var err error

  // lets environment variable override config file
  viper.AutomaticEnv()
  viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

  setDefaults()

  // Load discovery configurations

  viper.SetConfigFile(viper.GetString("config.discovery.path"))
  err = viper.ReadInConfig() // Find and read the config file
  if err != nil { // Handle errors reading the config file
    panic(fmt.Errorf("Fatal error config file: %s \n", err))
  }

  err = viper.Unmarshal(&Discovery)
  if err != nil {
    fmt.Printf("unable to decode into config struct, %v", err)
  }

  fmt.Println(Discovery.Hydra.Public.Url + Discovery.Hydra.Public.Endpoints.HealthReady);

  // Load app specific configurations

  viper.SetConfigFile(viper.GetString("config.app.path"))
  err = viper.ReadInConfig() // Find and read the config file
  if err != nil { // Handle errors reading the config file
    panic(fmt.Errorf("Fatal error config file: %s \n", err))
  }

  err = viper.Unmarshal(&App)
  if err != nil {
    fmt.Printf("unable to decode into config struct, %v", err)
  }

  Self.Url                    = viper.GetString("aap.ui.public.url")
  Self.Port                   = viper.GetString("aap.ui.public.port")
  Self.CsrfAuthKey            = viper.GetString("aap.ui.csrf.auth.key")
  Self.ClientId               = viper.GetString("aap.ui.oauth2.client.id")
  Self.ClientSecret           = viper.GetString("aap.ui.oauth2.client.secret")
  Self.RequiredScopes         = []string{"openid", "cpbe.authorize"}

}

func getEnv(name string) string {
  return os.Getenv(name)
}

func getEnvOrDefault(name string, def string) string {
  r := getEnv(name)

  if r == "" {
    r = def
  }

  return r
}

func getEnvStrict(name string) string {
  r := getEnv(name)

  if r == "" {
    panic("Missing environment variable: " + name)
  }

  return r
}

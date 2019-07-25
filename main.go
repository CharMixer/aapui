package main

import (
  "fmt"
  "net/url"

  "golang.org/x/net/context"
  //"golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"

  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  "github.com/atarantini/ginrequestid"

  oidc "github.com/coreos/go-oidc"

  "golang-cp-fe/config"
  "golang-cp-fe/environment"
  "golang-cp-fe/controllers"
)

func init() {
  config.InitConfigurations()
}

func main() {

  provider, err := oidc.NewProvider(context.Background(), config.Discovery.Hydra.Public.Url + "/")
  if err != nil {
    fmt.Println(err)
    return
  }

  // CpFe needs to be able as an App using client_id to access CpBe endpoints. Using client credentials flow
  cpbeConfig := &clientcredentials.Config{
    ClientID:  config.App.Oauth2.Client.Id,
    ClientSecret: config.App.Oauth2.Client.Secret,
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.App.Oauth2.Scopes.Required,
    EndpointParams: url.Values{"audience": {"cpbe"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  // Setup app state variables. Can be used in handler functions by doing closures see exchangeAuthorizationCodeCallback
  env := &environment.State{
    Provider: provider,
    CpBeConfig: cpbeConfig,
  }

  // Setup routes to use, this defines log for debug log
  routes := map[string]environment.Route{
    "/": environment.Route{
       URL: "/",
       LogId: "cpfe://",
    },
    "/authorize": environment.Route{
      URL: "/authorize",
      LogId: "cpfe://authorize",
    },
  }

  r := gin.Default()
  r.Use(ginrequestid.RequestId())

  // Use CSRF on all our forms.
  adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.App.Csrf.AuthKey), csrf.Secure(true)))
  // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

  r.Static("/public", "public")
  r.LoadHTMLGlob("views/*")


  ep := r.Group("/")
  ep.Use(adapterCSRF)
  {
    // FIXME: Should these endpoints be protected? aka requiring authentication before access?
    ep.GET(routes["/"].URL, controllers.ShowAuthorization(env, routes["/"]))

    ep.GET(routes["/authorize"].URL, controllers.ShowAuthorization(env, routes["/authorize"]))
    ep.POST(routes["/authorize"].URL, controllers.SubmitAuthorization(env, routes["/authorize"]))
  }

  r.RunTLS(":" + config.App.Serve.Public.Port, config.App.Serve.Tls.Cert.Path, config.App.Serve.Tls.Key.Path)
}

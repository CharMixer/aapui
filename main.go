package main

import (
  //"fmt"
  "net/url"
  "os"

  "golang.org/x/net/context"
  //"golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"

  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  "github.com/atarantini/ginrequestid"

  oidc "github.com/coreos/go-oidc"

  "golang-cp-fe/config"
  "golang-cp-fe/environment"
  "golang-cp-fe/controllers"

  "github.com/pborman/getopt"
)

const app = "cpfe"

func init() {
  config.InitConfigurations()
}

func main() {

  appFields := logrus.Fields{
    "appname": app,
    "func": "main",
  }

  provider, err := oidc.NewProvider(context.Background(), config.GetString("hydra.public.url") + "/")
  if err != nil {
    logrus.WithFields(appFields).WithFields(logrus.Fields{"component": "Hydra Provider"}).Fatal("oidc.NewProvider" + err.Error())
    return
  }

  // CpFe needs to be able as an App using client_id to access CpBe endpoints. Using client credentials flow
  cpbeConfig := &clientcredentials.Config{
    ClientID:  config.GetString("oauth2.client.id"),
    ClientSecret: config.GetString("oauth2.client.secret"),
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.GetStringSlice("oauth2.scopes.required"),
    EndpointParams: url.Values{"audience": {"cpbe"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  // Setup app state variables. Can be used in handler functions by doing closures see exchangeAuthorizationCodeCallback
  env := &environment.State{
    AppName: app,
    Provider: provider,
    CpBeConfig: cpbeConfig,
  }

  optServe := getopt.BoolLong("serve", 0, "Serve application")
  optHelp := getopt.BoolLong("help", 0, "Help")
  getopt.Parse()

  if *optHelp {
    getopt.Usage()
    os.Exit(0)
  }

  if *optServe {
    serve(env)
  } else {
    getopt.Usage()
    os.Exit(0)
  }

}

func serve(env *environment.State) {
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
  r.Use(logger(env))

  // Use CSRF on all our forms.
  adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.GetString("csrf.authKey")), csrf.Secure(true)))
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

  r.RunTLS(":" + config.GetString("serve.public.port"), config.GetString("serve.tls.cert.path"), config.GetString("serve.tls.key.path"))
}

func logger(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    var requestId string = c.MustGet(environment.RequestIdKey).(string)
    logger := logrus.New() // Use this to direct request log somewhere else than app log
    //logger.SetFormatter(&logrus.JSONFormatter{})
    requestLog := logger.WithFields(logrus.Fields{
      "appname": env.AppName,
      "requestid": requestId,
    })
    c.Set(environment.LogKey, requestLog)
    c.Next()
  }
  return gin.HandlerFunc(fn)
}

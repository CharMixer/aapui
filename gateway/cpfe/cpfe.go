package cpfe

import (
  _ "errors"
  _ "fmt"

  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
)

func RequestAccessTokenForCpBe(provider *clientcredentials.Config) (*oauth2.Token, error) {
  var token *oauth2.Token
  token, err := provider.Token(oauth2.NoContext)
  if err != nil {
    return token, err
  }
  return token, nil
}

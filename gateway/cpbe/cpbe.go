package cpbe

import (
  "net/http"
  "encoding/json"
  "io/ioutil"
  "bytes"
  //"fmt"

  "golang.org/x/net/context"
  "golang.org/x/oauth2/clientcredentials"
)

type AuthorizeRequest struct {
  Challenge                   string            `json:"challenge" binding:"required"`
  GrantScopes                 []string          `json:"grant_scopes,omitempty"`
}

type AuthorizeResponse struct {
  Challenge                   string            `json:"challenge" binding:"required"`
  Authorized                  bool              `json:"authorized" binding:"required"`
  GrantScopes                 []string          `json:"grant_scopes,omitempty"`
  RequestedScopes             []string          `json:"requested_scopes,omitempty"`
  RedirectTo                  string            `json:"redirect_to,omitempty`
}

type RejectRequest struct {
  Challenge                   string            `json:"challenge" binding:"required"`
}

type RejectResponse struct {
  RedirectTo                  string            `json:"redirect_to" binding:"required"`
}

type ConsentRequest struct {
  Subject string `json:"sub" binding:"required"`
  App string `json:"app" binding:"required"`
}

type CpBeClient struct {
  *http.Client
}

func NewCpBeClient(config *clientcredentials.Config) *CpBeClient {
  ctx := context.Background()
  client := config.Client(ctx)
  return &CpBeClient{client}
}

func FetchConsents(authorizationsUrl string, client *CpBeClient, consentRequest ConsentRequest) ([]string, error) {

  rawRequest, err := http.NewRequest("GET", authorizationsUrl, nil)
  if err != nil {
    return nil, err
  }

  query := rawRequest.URL.Query()
  query.Add("id", consentRequest.Subject)
  query.Add("app", consentRequest.App)
  rawRequest.URL.RawQuery = query.Encode()

  rawResponse, err := client.Do(rawRequest)
  if err != nil {
    return nil, err
  }

  responseData, err := ioutil.ReadAll(rawResponse.Body)
  if err != nil {
    return nil, err
  }

  var grantedConsents []string
  err = json.Unmarshal(responseData, &grantedConsents)
  if err != nil {
    return nil, err
  }
  return grantedConsents, nil
}

func Authorize(authorizeUrl string, client *CpBeClient, authorizeRequest AuthorizeRequest) (AuthorizeResponse, error) {
  var authorizeResponse AuthorizeResponse

  body, err := json.Marshal(authorizeRequest)
  if err != nil {
    return authorizeResponse, err
  }

  var data = bytes.NewBuffer(body)

  request, err := http.NewRequest("POST", authorizeUrl, data)
  if err != nil {
    return authorizeResponse, err
  }

  response, err := client.Do(request)
  if err != nil {
     return authorizeResponse, err
  }

  responseData, err := ioutil.ReadAll(response.Body)
  if err != nil {
    return authorizeResponse, err
  }

  err = json.Unmarshal(responseData, &authorizeResponse)
  if err != nil {
    return authorizeResponse, err
  }
  return authorizeResponse, nil
}

func Reject(authorizeUrl string, client *CpBeClient, authorizeRequest RejectRequest) (RejectResponse, error) {
  var rejectResponse RejectResponse

  return rejectResponse, nil
}

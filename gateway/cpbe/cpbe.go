package cpbe

import (
  "net/http"
  "encoding/json"
  "io/ioutil"
  "fmt"
  "bytes"

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

type CpBeClient struct {
  *http.Client
}

func NewCpBeClient(config *clientcredentials.Config) *CpBeClient {
  ctx := context.Background()
  client := config.Client(ctx)
  return &CpBeClient{client}
}

func Authorize(authorizeUrl string, client *CpBeClient, authorizeRequest AuthorizeRequest) (AuthorizeResponse, error) {
  var authorizeResponse AuthorizeResponse

  body, _ := json.Marshal(authorizeRequest)

  var data = bytes.NewBuffer(body)

  request, _ := http.NewRequest("POST", authorizeUrl, data)

fmt.Println(request)

  response, err := client.Do(request)
  if err != nil {
     return authorizeResponse, err
  }

  responseData, _ := ioutil.ReadAll(response.Body)

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

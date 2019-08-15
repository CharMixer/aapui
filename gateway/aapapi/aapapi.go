package aapapi

import (
  "net/http"
  "encoding/json"
  "io/ioutil"
  "bytes"
  "strings"
  "errors"
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
  RedirectTo                  string            `json:"redirect_to,omitempty"`
  Subject                     string            `json:"subject,omitempty"`
  ClientId                    string            `json:"client_id,omitempty"`
}

type RejectRequest struct {
  Challenge                   string            `json:"challenge" binding:"required"`
}

type RejectResponse struct {
  RedirectTo                  string            `json:"redirect_to" binding:"required"`
}

type ConsentRequest struct {
  Subject string `json:"sub" binding:"required"`
  ClientId string `json:"client_id,omitempty"`
  GrantedScopes []string `json:"granted_scopes,omitempty"`
  RevokedScopes []string `json:"revoked_scopes,omitempty"`
  RequestedScopes []string `json:"requested_scopes,omitempty"`
}

/*type ConsentResponse struct {

}*/

type AapApiClient struct {
  *http.Client
}

func NewAapApiClient(config *clientcredentials.Config) *AapApiClient {
  ctx := context.Background()
  client := config.Client(ctx)
  return &AapApiClient{client}
}

func CreateConsents(authorizationsUrl string, client *AapApiClient, consentRequest ConsentRequest) ([]string, error) {

  body, err := json.Marshal(consentRequest)
  if err != nil {
    return nil, err
  }

  var data = bytes.NewBuffer(body)

  request, err := http.NewRequest("POST", authorizationsUrl, data)
  if err != nil {
    return nil, err
  }

  response, err := client.Do(request)
  if err != nil {
     return nil, err
  }

  responseData, err := ioutil.ReadAll(response.Body)
  if err != nil {
    return nil, err
  }

  if response.StatusCode != 200 {
    return nil, errors.New("Failed to create consents, status: " + string(response.StatusCode) + ", error="+string(responseData))
  }

  var grantedConsents []string
  err = json.Unmarshal(responseData, &grantedConsents)
  if err != nil {
    return nil, err
  }

  return grantedConsents, nil
}

func FetchConsents(authorizationsUrl string, client *AapApiClient, consentRequest ConsentRequest) ([]string, error) {

  request, err := http.NewRequest("GET", authorizationsUrl, nil)
  if err != nil {
    return nil, err
  }

  query := request.URL.Query()
  query.Add("id", consentRequest.Subject)
  if consentRequest.ClientId != "" {
    query.Add("client_id", consentRequest.ClientId)
  }
  if len(consentRequest.RequestedScopes) > 0 {
    query.Add("scope", strings.Join(consentRequest.RequestedScopes, ","))
  }
  request.URL.RawQuery = query.Encode()

  response, err := client.Do(request)
  if err != nil {
    return nil, err
  }

  responseData, err := ioutil.ReadAll(response.Body)
  if err != nil {
    return nil, err
  }

  if response.StatusCode != 200 {
    return nil, errors.New("Failed to fetch consents, status: " + string(response.StatusCode) + ", error="+string(responseData))
  }

  var grantedConsents []string
  err = json.Unmarshal(responseData, &grantedConsents)
  if err != nil {
    return nil, err
  }
  return grantedConsents, nil
}

func Authorize(authorizeUrl string, client *AapApiClient, authorizeRequest AuthorizeRequest) (AuthorizeResponse, error) {
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

  if response.StatusCode != 200 {
    return authorizeResponse, errors.New("Failed to authorize, status: " + string(response.StatusCode) + ", error="+string(responseData))
  }

  err = json.Unmarshal(responseData, &authorizeResponse)
  if err != nil {
    return authorizeResponse, err
  }

  return authorizeResponse, nil
}

func Reject(authorizeUrl string, client *AapApiClient, rejectRequest RejectRequest) (RejectResponse, error) {
  var rejectResponse RejectResponse

  body, err := json.Marshal(rejectRequest)
  if err != nil {
    return rejectResponse, err
  }
  var data = bytes.NewBuffer(body)

  request, err := http.NewRequest("POST", authorizeUrl, data)
  if err != nil {
    return rejectResponse, err
  }

  response, err := client.Do(request)
  if err != nil {
     return rejectResponse, err
  }

  responseData, err := ioutil.ReadAll(response.Body)
  if err != nil {
    return rejectResponse, err
  }

  if response.StatusCode != 200 {
    return rejectResponse, errors.New("Failed to reject, status: " + string(response.StatusCode) + ", error="+string(responseData))
  }

  err = json.Unmarshal(responseData, &rejectResponse)
  if err != nil {
    return rejectResponse, err
  }

  return rejectResponse, nil
}

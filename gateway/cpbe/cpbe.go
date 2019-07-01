package cpbe

import (
  "net/http"
  "encoding/json"
  "io/ioutil"
  "fmt"
  "bytes"
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

func Authorize(authorizeUrl string, client *http.Client, authorizeRequest AuthorizeRequest) (AuthorizeResponse, error) {
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

func Reject(authorizeUrl string, client *http.Client, authorizeRequest RejectRequest) (RejectResponse, error) {
  var rejectResponse RejectResponse
  return rejectResponse, nil
}
/*
func GetAuthorizationsAuthorize(authorizeUrl string, client *http.Client, challenge string) (GetAuthorizationsAuthorizeResponse, error) {
  var authorizeResponse GetAuthorizationsAuthorizeResponse

  request, _ := http.NewRequest("GET", authorizeUrl, nil)

  query := request.URL.Query()
  query.Add("challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, _ := client.Do(request)

  if response.StatusCode == 403 {
    return authorizeResponse, fmt.Errorf("Authorization failed for request to cpbe for challenge %s", challenge)
  }
  if response.StatusCode == 404 {
    return authorizeResponse, fmt.Errorf("Consent request not found for challenge %s", challenge)
  }

  responseData, _ := ioutil.ReadAll(response.Body)

  json.Unmarshal(responseData, &authorizeResponse)

  return authorizeResponse, nil
}
*/

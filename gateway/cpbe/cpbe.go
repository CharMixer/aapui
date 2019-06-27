package cpbe

import (
  "golang-cp-fe/config"
  "net/http"
  "encoding/json"
  "io/ioutil"
  "fmt"
  "bytes"
)

type GetAuthorizationsAuthorizeResponse struct {
  RequestedScopes             []string          `json:"requested_scopes"`
}

type PostAuthorizationsAuthorizeRequest struct {
  GrantScopes                 []string          `json:"grant_scopes" binding:"required"`
  Challenge                   string            `json:"challenge" binding:"required"`
  Session                     struct {
    AccessToken                 string            `json:"access_token"`
    IdToken                     string            `json:"id_token"`
  } `json:"session" binding:"required"`
}

type PostAuthorizationsAuthorizeResponse struct {
  GrantScopes                 []string          `json:"grant_scopes" binding:"required"`
  RequestedScopes             []string          `json:"requested_scopes" binding:"required"`
  Authorized                  bool              `json:"authorized" binding:"required"`
  RedirectTo                  string            `json:"redirect_to" binding:"required"`
}

func getDefaultHeaders() map[string][]string {
  return map[string][]string{
    "Content-Type": []string{"application/json"},
    "Accept": []string{"application/json"},
  }
}


func getDefaultHeadersWithAuthentication(accessToken string) map[string][]string {
  return map[string][]string{
    "Content-Type": []string{"application/json"},
    "Accept": []string{"application/json"},
    "Authorization": []string{"Bearer " + accessToken},
  }
}

func Authorize(authorizeUrl string, client *http.Client, authorizeRequest PostAuthorizationsAuthorizeRequest) (PostAuthorizationsAuthorizeResponse, error) {
   var authorizeResponse PostAuthorizationsAuthorizeResponse

   body, _ := json.Marshal(authorizeRequest)

   var data = bytes.NewBuffer(body)

   request, _ := http.NewRequest("POST", authorizeUrl, data)

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

func GetAuthorizationsAuthorize(challenge string) (GetAuthorizationsAuthorizeResponse, error) {
  var authorizeResponse GetAuthorizationsAuthorizeResponse

  client := &http.Client{}

  request, _ := http.NewRequest("GET", config.CpBe.AuthorizationsAuthorizeUrl, nil)
  request.Header = getDefaultHeaders()

  query := request.URL.Query()
  query.Add("challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, _ := client.Do(request)

  if response.StatusCode == 404 {
    return authorizeResponse, fmt.Errorf("CP-be: consent request not found from challenge %s", challenge)
  }

  responseData, _ := ioutil.ReadAll(response.Body)

  json.Unmarshal(responseData, &authorizeResponse)

  return authorizeResponse, nil
}

func PostAuthorizationsAuthorize(requestInterface PostAuthorizationsAuthorizeRequest) (PostAuthorizationsAuthorizeResponse, error) {
  var authorizeResponse PostAuthorizationsAuthorizeResponse

  client := &http.Client{}

  body, _ := json.Marshal(requestInterface)

  request, _ := http.NewRequest("POST", config.CpBe.AuthorizationsAuthorizeUrl, bytes.NewBuffer(body))
  request.Header = getDefaultHeaders()

  response, _ := client.Do(request)

  if response.StatusCode == 404 {
    return authorizeResponse, fmt.Errorf("CP-be: consent request not found from challenge %s", requestInterface.Challenge)
  }

  responseData, _ := ioutil.ReadAll(response.Body)

  json.Unmarshal(responseData, &authorizeResponse)

  return authorizeResponse, nil
}

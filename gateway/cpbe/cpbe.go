package cpbe

import (
  "golang-cp-fe/config"
  "golang-cp-fe/interfaces"
  "net/http"
  "encoding/json"
  "io/ioutil"
  "fmt"
  "bytes"
)

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

func Authorize(authorizeUrl string, client *http.Client, authorizeRequest interfaces.CPBePostAuthorizationsAuthorizeRequest) (interfaces.CPBePostAuthorizationsAuthorizeResponse, error) {
   var authorizeResponse interfaces.CPBePostAuthorizationsAuthorizeResponse


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

func GetAuthorizationsAuthorize(challenge string) (interfaces.CPBeGetAuthorizationsAuthorizeResponse, error) {
  var cpBeGetAuthorizationsAuthorizeResponse interfaces.CPBeGetAuthorizationsAuthorizeResponse

  client := &http.Client{}

  request, _ := http.NewRequest("GET", config.CpBe.AuthorizationsAuthorizeUrl, nil)
  request.Header = getDefaultHeaders()

  query := request.URL.Query()
  query.Add("challenge", challenge)
  request.URL.RawQuery = query.Encode()

  response, _ := client.Do(request)

  if response.StatusCode == 404 {
    return cpBeGetAuthorizationsAuthorizeResponse, fmt.Errorf("CP-be: consent request not found from challenge %s", challenge)
  }

  responseData, _ := ioutil.ReadAll(response.Body)

  json.Unmarshal(responseData, &cpBeGetAuthorizationsAuthorizeResponse)

  return cpBeGetAuthorizationsAuthorizeResponse, nil
}

func PostAuthorizationsAuthorize(requestInterface interfaces.CPBePostAuthorizationsAuthorizeRequest) (interfaces.CPBePostAuthorizationsAuthorizeResponse, error) {
  var responseInterface interfaces.CPBePostAuthorizationsAuthorizeResponse

  client := &http.Client{}

  body, _ := json.Marshal(requestInterface)

  request, _ := http.NewRequest("POST", config.CpBe.AuthorizationsAuthorizeUrl, bytes.NewBuffer(body))
  request.Header = getDefaultHeaders()

  response, _ := client.Do(request)

  if response.StatusCode == 404 {
    return responseInterface, fmt.Errorf("CP-be: consent request not found from challenge %s", requestInterface.Challenge)
  }

  responseData, _ := ioutil.ReadAll(response.Body)

  json.Unmarshal(responseData, &responseInterface)

  return responseInterface, nil
}

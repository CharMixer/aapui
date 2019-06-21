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

func GetAuthorizationsAuthorize(challenge string) (interfaces.CPBeGetAuthorizationsAuthorizeResponse, error) {
  var cpBeGetAuthorizationsAuthorizeResponse interfaces.CPBeGetAuthorizationsAuthorizeResponse

  client := &http.Client{}

  request, _ := http.NewRequest("GET", config.CPBe.AuthorizationsAuthorizeUrl, nil)
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

  request, _ := http.NewRequest("POST", config.CPBe.AuthorizationsAuthorizeUrl, bytes.NewBuffer(body))
  request.Header = getDefaultHeaders()

  response, _ := client.Do(request)

  if response.StatusCode == 404 {
    return responseInterface, fmt.Errorf("CP-be: consent request not found from challenge %s", requestInterface.Challenge)
  }

  responseData, _ := ioutil.ReadAll(response.Body)

  json.Unmarshal(responseData, &responseInterface)

  return responseInterface, nil
}

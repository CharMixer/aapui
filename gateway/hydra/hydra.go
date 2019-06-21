package hydra

import (
  _ "golang-cp-fe/config"
  _ "golang-cp-fe/interfaces"
  _ "net/http"
  _ "bytes"
  _ "encoding/json"
  _ "io/ioutil"
  _ "fmt"
)

func getDefaultHeaders() map[string][]string {
  return map[string][]string{
    "Content-Type": []string{"application/json"},
    "Accept": []string{"application/json"},
  }
}

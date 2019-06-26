package interfaces

type CPBeGetAuthorizationsAuthorizeResponse struct {
  RequestedScopes             []string          `json:"requested_scopes"`
}

type CPBePostAuthorizationsAuthorizeRequest struct {
  GrantScopes                 []string          `json:"grant_scopes" binding:"required"`
  Challenge                   string            `json:"challenge" binding:"required"`
  Session                     struct {
    AccessToken                 string            `json:"access_token"`
    IdToken                     string            `json:"id_token"`
  } `json:"session" binding:"required"`
}

type CPBePostAuthorizationsAuthorizeResponse struct {
  GrantScopes                 []string          `json:"grant_scopes" binding:"required"`
  RequestedScopes             []string          `json:"requested_scopes" binding:"required"`
  Authorized                  bool              `json:"authorized" binding:"required"`
  RedirectTo                  string            `json:"redirect_to" binding:"required"`
}

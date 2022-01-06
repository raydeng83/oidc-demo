package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/raydeng83/oidc-demo/authorizationserver"
	goauth "golang.org/x/oauth2"
	"os"
)

// A valid oauth2 client (check the store) that additionally requests an OpenID Connect id token
var clientConf = goauth.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	RedirectURL:  "http://localhost:3846/callback",
	Scopes:       []string{"photos", "openid", "offline"},
	Endpoint: goauth.Endpoint{
		TokenURL: "http://localhost:8080/oauth2/token",
		AuthURL:  "http://localhost:8080/oauth2/auth",
	},
}

func main() {
	mux := gin.Default()

	// ### oauth2 server ###
	authorizationserver.RegisterHandlers(mux) // the authorization server (fosite)

	port := "8080"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	fmt.Println("Please open your webbrowser at http://localhost:" + port)
	//log.Fatal(http.ListenAndServe("localhost:"+port, nil))
	mux.Run("bi-sso-server:8080")
}

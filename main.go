package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/raydeng83/oidc-demo/authorizationserver"
	"github.com/raydeng83/oidc-demo/handlers"
	goauth "golang.org/x/oauth2"
	"net/http"
)

var authHandler *handlers.AuthHandler

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
	store := cookie.NewStore([]byte("secret"))
	mux.Use(sessions.Sessions("sso-session", store))

	mux.Static("/css", "./static/css")
	mux.Static("/vendor", "./static/vendor")
	mux.Static("/js", "./static/js")

	mux.LoadHTMLGlob("templates/*.tmpl")

	// ### oauth2 server ###
	authorizationserver.RegisterHandlers(mux) // the authorization server (fosite)
	mux.GET("/login", handlers.SignInGet)
	mux.POST("/login", handlers.SignInPost)
	mux.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusSeeOther, "/home")
	})

	authorized := mux.Group("/")
	authorized.Use(authHandler.AuthMiddleware())
	authorized.GET("/home", func(c *gin.Context) {
		c.HTML(200, "home.tmpl", gin.H{})
	})

	mux.Run("localhost:8080")
}

package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/raydeng83/oidc-demo/authorizationserver"
	"github.com/raydeng83/oidc-demo/handlers"
	"github.com/raydeng83/oidc-demo/models"
	"github.com/raydeng83/oidc-demo/repository"
	"golang.org/x/crypto/bcrypt"
	goauth "golang.org/x/oauth2"
	"log"
	"net/http"
)

var authHandler *handlers.AuthHandler

// A valid oauth2 client (check the store) that additionally requests an OpenID Connect id token
var clientConf = goauth.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	RedirectURL:  "http://localhost:3846/callback",
	Scopes:       []string{"photos", "openid", "offline", "profile"},
	Endpoint: goauth.Endpoint{
		TokenURL: "http://localhost:8080/oauth2/token",
		AuthURL:  "http://localhost:8080/oauth2/auth",
	},
}

func main() {
	db := repository.InitDb()
	db.AutoMigrate(&models.User{})

	// init users in repo
	var users []models.User
	err := repository.GetUsers(&users)
	if err != nil {
		log.Println("error finding users from repo")
	}
	if len(users) == 0 {
		passwordBytes, err := bcrypt.GenerateFromPassword([]byte("pwd123"), 12)
		admin := models.User{Username: "admin", Password: string(passwordBytes), Email: "admin@example.com", FirstName: "admin", LastName: "admin"}
		_, err = repository.CreateUser(&admin)
		if err != nil {
			log.Println("cannot create admin user")
		}

		ldeng := models.User{Username: "ldeng", Password: string(passwordBytes), Email: "ldeng@example.com", FirstName: "ldeng", LastName: "ldeng"}
		_, err = repository.CreateUser(&ldeng)
		if err != nil {
			log.Println("cannot create ldeng user")
		}
	}

	mux := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	mux.Use(sessions.Sessions("sso-session", store))

	mux.Static("/css", "./static/css")
	mux.Static("/vendor", "./static/vendor")
	mux.Static("/js", "./static/js")

	mux.LoadHTMLGlob("templates/*.tmpl")

	mux.GET("/login", handlers.SignInGet)
	mux.POST("/login", handlers.SignInPost)
	mux.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusSeeOther, "/home")
	})
	mux.GET("/logout", handlers.Logout)

	authorized := mux.Group("/")
	authorized.Any("/oauth2/token", authorizationserver.TokenEndpoint) // token endpoint should be accessible without login
	authorized.Use(authHandler.AuthMiddleware())
	{
		authorized.GET("/home", func(c *gin.Context) {
			c.HTML(200, "home.tmpl", gin.H{
				"username": handlers.SessionUser.Username,
			})
		})

		// ### oauth2 server ###
		// the authorization server (fosite)
		authorized.Any("/oauth2/auth", authorizationserver.AuthEndpoint)
	}

	mux.Run("localhost:8080")
}

package handlers

import (
	"context"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/rs/xid"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type AuthHandler struct {
	ctx context.Context
}

type JWTOutput struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

func SignInGet(c *gin.Context) {
	c.HTML(200, "login.tmpl", gin.H{})
}

func SignInPost(c *gin.Context) {
	r := c.Request
	err := r.ParseForm()
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to parse the request form"})
		return
	}

	// check url parameter state
	//request := c.Request.URL.String()
	//var state string
	//urlParts := make([]string, 0)
	//if strings.Contains(request, "?") {
	//	urlParts = strings.Split(request, "?")
	//	state, _ = url.QueryUnescape(urlParts[1])
	//}

	// get username and password from form post
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if username != "ldeng" || password != "pwd123" {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	// generate user session
	session := sessions.Default(c)
	sessionToken := xid.New().String()
	session.Set("sessionToken", sessionToken)
	session.Save()
	c.Redirect(http.StatusFound, "/home")
}

func (handler *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		sessionToken := session.Get("sessionToken")

		if sessionToken == nil {
			rawRequest, err := ioutil.ReadAll(c.Request.Body)
			if err != nil {
				// Handle error
				log.Println(err)
			}
			request := string(rawRequest)
			c.Redirect(http.StatusFound, "/login?"+request)
			c.Abort()
		} else {
			c.Next()
		}
	}
}

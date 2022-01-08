package handlers

import (
	"context"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/rs/xid"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
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
	// record url parameters as state
	request := c.Request.URL.String()
	var state string
	urlParts := make([]string, 0)
	if strings.Contains(request, "?") {
		urlParts = strings.Split(request, "?")
		state, _ = url.QueryUnescape(urlParts[1])
	}

	c.HTML(http.StatusUnauthorized, "login.tmpl", gin.H{
		"state": state,
	})
}

func SignInPost(c *gin.Context) {
	r := c.Request
	err := r.ParseForm()
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to parse the request form"})
		return
	}

	// check url parameter state
	request := c.Request.URL.String()
	var state string
	urlParts := make([]string, 0)
	if strings.Contains(request, "?") {
		urlParts = strings.Split(request, "?")
		state, _ = url.QueryUnescape(urlParts[1])
	}

	// get username and password from form post
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if username != "ldeng" || password != "pwd123" {
		c.HTML(http.StatusOK, "login.tmpl", gin.H{
			"error": "Authentication failed",
			"state": state,
		})
		return
	}

	// generate user session
	session := sessions.Default(c)
	sessionToken := xid.New().String()
	session.Set("ssoToken", sessionToken)
	session.Save()

	// check OAuth request
	var m = map[string]string{}
	paramParts := strings.Split(state, "&")

	for _, p := range paramParts {
		f := strings.SplitN(p, "=", 2)
		m[f[0]] = f[1]
	}

	originalRequestPath := m["original_request_path"]

	decodedRequestUrl, _ := url.QueryUnescape(r.URL.String())

	if originalRequestPath != "" {
		c.Redirect(http.StatusFound, originalRequestPath+"?"+stripQueryParam(decodedRequestUrl, "original_request_path"))
	} else {
		c.Redirect(http.StatusFound, "/home")
	}
}

func Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/login")
}

func (handler *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		sessionToken := session.Get("ssoToken")

		if sessionToken == nil {
			originalRequestPath := c.Request.URL.Path

			// check request body
			rawState, err := ioutil.ReadAll(c.Request.Body)
			if err != nil {
				// Handle error
				log.Println(err)
			}
			state := string(rawState)
			if len(state) > 0 {
				c.Redirect(http.StatusFound, "/login?original_request_path="+originalRequestPath+"&"+state)
				c.Abort()
			}

			state = "" // clear state

			// check request url parameter
			requestString := c.Request.URL.String()
			urlParts := make([]string, 0)
			if strings.Contains(requestString, "?") {
				urlParts = strings.Split(requestString, "?")
				state, _ = url.QueryUnescape(urlParts[1])
			}

			if len(state) > 0 {
				c.Redirect(http.StatusFound, "/login?original_request_path="+originalRequestPath+"&"+state)
				c.Abort()
			}

			c.Redirect(http.StatusFound, "/login")
			c.Abort()
		} else {
			c.Next()
		}
	}
}

func stripQueryParam(inURL string, stripKey string) string {
	u, err := url.Parse(inURL)
	if err != nil {
		fmt.Println("Error removing parameter " + stripKey + " from " + inURL)
		return inURL
	}
	q := u.Query()
	q.Del(stripKey)
	u.RawQuery = q.Encode()

	return strings.SplitN(u.String(), "?", 2)[1]
}

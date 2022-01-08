package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/raydeng83/oidc-demo/models"
	"github.com/raydeng83/oidc-demo/repository"
	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var SessionUser models.User

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
		state = urlParts[1]
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

	// if username is not found
	user, err := repository.GetUserByUsername(username)
	if err != nil {
		log.Printf("Error finding user with username %s\n", username)
		return
	}

	// validate username and password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))

	if err != nil {
		c.HTML(http.StatusUnauthorized, "login.tmpl", gin.H{
			"error": "Authentication failed",
			"state": state,
		})
		return
	}

	// generate user session
	session := sessions.Default(c)
	sessionToken := xid.New().String()
	marshalledUser, _ := json.Marshal(user)
	session.Set("sessionUser", string(marshalledUser))
	session.Set("ssoToken", sessionToken)
	session.Save()

	c.Set("sessionUser", *user) // set user in session
	SessionUser = *user         // sessionUser is file level var

	// check url parameter exists
	var m = map[string]string{}

	if len(state) > 0 {
		paramParts := strings.Split(state, "&")

		for _, p := range paramParts {
			f := strings.SplitN(p, "=", 2)
			m[f[0]] = f[1]
		}
	}

	targetPath := m["target_path"]

	decodedRequestUrl, _ := url.QueryUnescape(r.URL.String())

	if targetPath != "" {
		c.Redirect(http.StatusFound, targetPath+"?"+stripQueryParam(decodedRequestUrl, "target_path"))
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
		sessionUserJson := session.Get("sessionUser")

		if sessionToken == nil {
			targetPath := c.Request.URL.Path

			// check request body
			rawState, err := ioutil.ReadAll(c.Request.Body)
			if err != nil {
				// Handle error
				log.Println(err)
			}
			state := string(rawState)
			if len(state) > 0 {
				c.Redirect(http.StatusFound, "/login?target_path="+targetPath+"&"+state)
				c.Abort()
			}

			state = "" // clear state

			// check request url parameter
			requestString := c.Request.URL.String()
			urlParts := make([]string, 0)
			if strings.Contains(requestString, "?") {
				urlParts = strings.Split(requestString, "?")
				state = urlParts[1]
			}

			if len(state) > 0 {
				c.Redirect(http.StatusFound, "/login?target_path="+targetPath+"&"+state)
				c.Abort()
			}

			c.Redirect(http.StatusFound, "/login")
			c.Abort()
		} else {
			sessionUserJsonString := sessionUserJson.(string)
			user := models.User{}
			json.Unmarshal([]byte(sessionUserJsonString), &user)
			SessionUser = user                // sessionUser is file level var
			c.Set("sessionUser", SessionUser) // set user in session
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

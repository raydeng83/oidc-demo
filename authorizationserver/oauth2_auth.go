package authorizationserver

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/url"
	"strings"
)

func AuthEndpoint(ctx *gin.Context) {
	req := ctx.Request
	rw := ctx.Writer
	ar, err := oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %+v", err)
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// get scope parameter
	params, err := url.ParseQuery(req.URL.String())
	if err != nil {
		log.Println("Requesting URL param parsing error")
	}

	s := params.Get("scope")
	var scopes []string
	if strings.Contains(s, "+") { // check if scopes are concatenated by '+'
		scopes = strings.Split(s, "+")
	} else {
		scopes = strings.Fields(s) // use whitespace as delimiter
	}

	for _, scope := range scopes {
		ar.GrantScope(scope)
	}

	mySessionData := newSession("peter")

	response, err := oauth2.NewAuthorizeResponse(ctx, ar, mySessionData)

	if err != nil {
		log.Printf("Error occurred in NewAuthorizeResponse: %+v", err)
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	oauth2.WriteAuthorizeResponse(rw, ar, response)
}

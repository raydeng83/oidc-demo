package authorizationserver

import (
	"github.com/gin-gonic/gin"
	"log"
)

func tokenEndpoint(ctx *gin.Context) {
	req := ctx.Request
	rw := ctx.Writer

	mySessionData := newSession("")

	accessRequest, err := oauth2.NewAccessRequest(ctx, req, mySessionData)

	if err != nil {
		log.Printf("Error occurred in NewAccessRequest: %+v", err)
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	if accessRequest.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range accessRequest.GetRequestedScopes() {
			accessRequest.GrantScope(scope)
		}
	}

	response, err := oauth2.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		log.Printf("Error occurred in NewAccessResponse: %+v", err)
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	oauth2.WriteAccessResponse(rw, accessRequest, response)

}

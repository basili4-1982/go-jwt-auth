package go_jwt_auth

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type IAuth interface {
	NewAccessToken(claims Claims, duration time.Duration) (string, error)
	NewRefreshToken(duration time.Duration) (string, error)
	ParseToken(reqToken string) (Claims, error)
}

type IClaims interface {
	Valid() error
	StandardClaims() jwt.StandardClaims
	SetStandardClaims(claims jwt.StandardClaims)
}

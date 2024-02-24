package go_jwt_auth

import (
	"time"
)

import "github.com/golang-jwt/jwt"

type Auth struct {
	SigningKey []byte
	method     jwt.SigningMethod
}

func NewAuth(signingKey []byte, method jwt.SigningMethod) *Auth {
	return &Auth{SigningKey: signingKey, method: method}
}

func (a Auth) NewAccessToken(claims IClaims, duration time.Duration) (string, error) {
	standardClaims := claims.StandardClaims()
	standardClaims.ExpiresAt = time.Now().Add(duration).Unix()
	claims.SetStandardClaims(standardClaims)

	token := jwt.NewWithClaims(a.method, claims)

	return token.SignedString(a.SigningKey)
}

func (a Auth) NewRefreshToken(duration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		standard: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(duration).Unix(),
		},
	})

	return token.SignedString(a.SigningKey)
}

func (a Auth) ParseToken(reqToken string, c IClaims) error {
	_, err := jwt.ParseWithClaims(reqToken, c, func(token *jwt.Token) (interface{}, error) {
		return a.SigningKey, nil
	})

	return err
}

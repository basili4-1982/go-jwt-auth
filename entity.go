package go_jwt_auth

import "github.com/golang-jwt/jwt"

type Claims struct {
	standard jwt.StandardClaims
}

func (c Claims) StandardClaims() jwt.StandardClaims {
	return c.standard
}

func (c Claims) Valid() error {
	return c.standard.Valid()
}

func (c *Claims) SetStandardClaims(claims jwt.StandardClaims) {
	c.standard = claims
}

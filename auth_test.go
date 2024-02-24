package go_jwt_auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
)

type myClaims struct {
	Claims
	ID   int32
	Role []string
}

func TestAuthToken(t *testing.T) {
	a := NewAuth([]byte("secret"), jwt.SigningMethodHS256)
	argClaims := &myClaims{
		ID:   1111,
		Role: []string{"admin"},
	}

	token, err := a.NewAccessToken(argClaims, 10*time.Second)
	require.NoError(t, err)

	actualClaims := &myClaims{}

	err = a.ParseToken(token, actualClaims)
	if err != nil {
		return
	}

	require.Equal(t, argClaims.ID, actualClaims.ID)
	require.Equal(t, argClaims.Role, actualClaims.Role)
}

func TestRefreshToken(t *testing.T) {
	a := NewAuth([]byte("secret"), jwt.SigningMethodHS256)

	token, err := a.NewRefreshToken(10 * time.Second)
	if err != nil {
		return
	}

	argClaims := &myClaims{}

	actualClaims := &myClaims{}
	err = a.ParseToken(token, actualClaims)
	if err != nil {
		return
	}

	require.Equal(t, argClaims.ID, actualClaims.ID)
	require.Equal(t, argClaims.Role, actualClaims.Role)
}

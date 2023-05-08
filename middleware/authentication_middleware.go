package middleware

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"jwtauthentication/models"
	"net/http"
	"strings"
)

func AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Authorization"] == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tknStr := r.Header.Get("Authorization")

		if len(tknStr) < 7 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var token string
		if strings.ToUpper(tknStr[0:7]) == "BEARER " {
			token = tknStr[7:]
		}

		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Initialize a new instance of `Claims`
		claims := &models.Claims{}

		// Parse the JWT string and store the result in `claims`.
		// Note that we are passing the key in this method as well. This method will return an error
		// if the token is invalid (if it has expired according to the expiry time we set on sign in),
		// or if the signature does not match
		tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte("my_secret_key"), nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !tkn.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user", claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

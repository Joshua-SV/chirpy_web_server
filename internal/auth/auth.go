package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	// get the hash string from bcrypt
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(passHash), nil
}

func CheckPasswordvsHash(password, hash string) error {
	// compare input password against real password
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	// create a claims struct for payload in json web token
	claims := &jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	}

	// create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// return string that will be used by the client
	return token.SignedString([]byte(tokenSecret))
}

// ValidateJWT verifies signature & standard claims, then returns the userID from Subject.
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	var claims jwt.RegisteredClaims

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (interface{}, error) {
		// Ensure we actually got HS256 (or a method you expect)
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid token")
		}

		// converts the string key to the appropriate type to use by the hash method to compare outputs
		return []byte(tokenSecret), nil
	})

	if err != nil || !token.Valid {
		return uuid.Nil, errors.New("invalid token")
	}

	// (Optional) you can also explicitly validate time-based claims:
	// if err := claims.Validate(jwt.WithLeeway(30 * time.Second)); err != nil { ... }

	// get the user uuid
	userId, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, errors.New("could not parse id")
	}
	return userId, nil
}

// retreive the JWT token sent by the client
func GetBearerToken(headers http.Header) (string, error) {
	//get the value usign the key header name
	value := headers.Get("Authorization")
	if value == "" {
		return "", errors.New("Authorization header missing")
	}

	// check for prefix
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return "", errors.New("authorization header format must be 'Bearer <token>'")
	}

	// trim prefix
	tokenStr := strings.TrimSpace(strings.TrimPrefix(value, prefix))
	if tokenStr == "" {
		return "", errors.New("token missing after 'Bearer '")
	}

	return tokenStr, nil
}

// function to create encoded 32-byte string for refresh token
func MakeRefreshToken() (string, error) {
	// create random 32-byte
	key := make([]byte, 32)
	// fills key with random data
	rand.Read(key)
	// encode byte to hex string
	token := hex.EncodeToString(key)

	return token, nil
}

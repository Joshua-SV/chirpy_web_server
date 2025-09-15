package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidate(t *testing.T) {
	secret := "test-secret"
	userID := uuid.New()

	t.Run("valid token", func(t *testing.T) {
		token, err := MakeJWT(userID, secret, time.Minute)
		if err != nil {
			t.Fatalf("MakeJWT error: %v", err)
		}
		got, err := ValidateJWT(token, secret)
		if err != nil {
			t.Fatalf("ValidateJWT error: %v", err)
		}
		if got != userID {
			t.Fatalf("want %v, got %v", userID, got)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		token, err := MakeJWT(userID, secret, -1*time.Second)
		if err != nil {
			t.Fatalf("MakeJWT error: %v", err)
		}
		if _, err := ValidateJWT(token, secret); err == nil {
			t.Fatalf("expected error for expired token; got nil")
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		token, err := MakeJWT(userID, secret, time.Minute)
		if err != nil {
			t.Fatalf("MakeJWT error: %v", err)
		}
		if _, err := ValidateJWT(token, "other-secret"); err == nil {
			t.Fatalf("expected error for wrong secret; got nil")
		}
	})
}

func TestHeaderToken(t *testing.T) {
	makeHeader := func(v string) http.Header {
		// decalre an empty header struct
		header := http.Header{}

		if v != "" {
			header.Set("Authorization", v)
		}
		return header
	}

	// create test cases
	tests := []struct {
		name      string
		authValue string
		wantToken string
		wantErr   bool
	}{
		{
			name:      "valid bearer",
			authValue: "Bearer abc.def.ghi",
			wantToken: "abc.def.ghi",
			wantErr:   false,
		},
		{
			name:      "missing header",
			authValue: "",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "wrong scheme",
			authValue: "Token abc",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "empty after bearer",
			authValue: "Bearer ",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "extra spaces after bearer",
			authValue: "Bearer    abc.def",
			wantToken: "abc.def",
			wantErr:   false,
		},
		{
			name:      "trailing spaces",
			authValue: "Bearer abc.def   ",
			wantToken: "abc.def",
			wantErr:   false,
		},
		{
			name:      "leading spaces before scheme (will fail with strict prefix)",
			authValue: "  Bearer abc.def",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "lowercase scheme (will fail with strict prefix)",
			authValue: "bearer abc.def",
			wantToken: "",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := GetBearerToken(makeHeader(tc.authValue))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			if token != tc.wantToken {
				t.Fatalf("token=%q, want %q", token, tc.wantToken)
			}
		})
	}
}

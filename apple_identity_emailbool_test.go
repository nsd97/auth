package auth

import (
	"encoding/json"
	"testing"
)

// Apple documents email_verified as either a JSON string ("true"/"false") or a
// JSON boolean (true/false) and sends the boolean form over the web /
// Services-ID flow (used by the macOS app). Both must decode without error and
// normalize the same way, so a valid Apple token is never rejected over the
// claim's JSON type.
func TestEmailVerifiedAcceptsStringAndBool(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    bool
	}{
		{"string true", `{"email":"a@b.com","email_verified":"true"}`, true},
		{"bool true", `{"email":"a@b.com","email_verified":true}`, true},
		{"string false", `{"email":"a@b.com","email_verified":"false"}`, false},
		{"bool false", `{"email":"a@b.com","email_verified":false}`, false},
		{"absent", `{"email":"a@b.com"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var claims appleIDTokenClaims
			if err := json.Unmarshal([]byte(c.payload), &claims); err != nil {
				t.Fatalf("unmarshal %s: %v", c.payload, err)
			}
			got := claims.EmailVerified == true || claims.EmailVerified == "true"
			if got != c.want {
				t.Errorf("payload %s: verified=%v, want %v", c.payload, got, c.want)
			}
		})
	}
}

package consoleauth

import (
	"strings"
	"testing"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	t.Parallel()
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected PHC prefix: %q", hash)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("correct password did not verify")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Fatal("wrong password verified")
	}
}

func TestHashPasswordDistinctSalts(t *testing.T) {
	t.Parallel()
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Fatal("two hashes of the same password are identical — salt not random")
	}
	if !VerifyPassword(h1, "same") || !VerifyPassword(h2, "same") {
		t.Fatal("both hashes should verify the same password")
	}
}

func TestHashPasswordEmpty(t *testing.T) {
	t.Parallel()
	if _, err := HashPassword(""); err != ErrEmptyPassword {
		t.Fatalf("empty password err = %v, want ErrEmptyPassword", err)
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	t.Parallel()
	valid, _ := HashPassword("pw")
	cases := []struct {
		name    string
		encoded string
	}{
		{"empty", ""},
		{"not-phc", "plaintext"},
		{"wrong-scheme", "$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"},
		{"wrong-version", "$argon2id$v=16$m=65536,t=3,p=4$c2FsdA$aGFzaA"},
		{"wrong-params", "$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$aGFzaA"},
		{"bad-salt-b64", "$argon2id$v=19$m=65536,t=3,p=4$!!!$aGFzaA"},
		{"bad-key-b64", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$!!!"},
		{"too-few-fields", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA"},
		{"empty-key", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if VerifyPassword(tc.encoded, "pw") {
				t.Fatalf("malformed hash %q verified", tc.encoded)
			}
		})
	}
	// A genuinely valid hash still verifies (guards against an over-strict parser).
	if !VerifyPassword(valid, "pw") {
		t.Fatal("valid hash failed to verify")
	}
	// Empty plaintext never verifies, even against a valid hash.
	if VerifyPassword(valid, "") {
		t.Fatal("empty plaintext verified")
	}
}

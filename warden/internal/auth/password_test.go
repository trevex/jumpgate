package auth

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "" {
		t.Fatal("empty hash")
	}
	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("correct password did not verify")
	}
	bad, err := VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("verify bad: %v", err)
	}
	if bad {
		t.Fatal("wrong password verified")
	}
}

func TestHashesAreSalted(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Fatal("two hashes of the same password are identical (missing random salt)")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("short", ""); err == nil {
		t.Fatal("accepted too-short password")
	}
	if err := ValidatePassword("password1234", ""); err == nil {
		t.Fatal("accepted common password")
	}
	if err := ValidatePassword("Password1234", ""); err == nil {
		t.Fatal("accepted common password in different case")
	}
	if err := ValidatePassword("a-perfectly-fine-passphrase", ""); err != nil {
		t.Fatalf("rejected good password: %v", err)
	}
}

func TestValidatePasswordRejectsReuse(t *testing.T) {
	h, _ := HashPassword("a-perfectly-fine-passphrase")
	if err := ValidatePassword("a-perfectly-fine-passphrase", h); err == nil {
		t.Fatal("accepted reuse of current password")
	}
}

func TestVerifyRejectsPathologicalParams(t *testing.T) {
	bad := "$argon2id$m=8388608,t=1,p=4$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcA"
	if _, err := VerifyPassword("x", bad); err == nil {
		t.Fatal("accepted pathological argon2 params")
	}
	badT := "$argon2id$m=65536,t=17,p=4$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcA"
	if _, err := VerifyPassword("x", badT); err == nil {
		t.Fatal("accepted out-of-range t")
	}
	badP := "$argon2id$m=65536,t=1,p=17$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcA"
	if _, err := VerifyPassword("x", badP); err == nil {
		t.Fatal("accepted out-of-range p")
	}
}

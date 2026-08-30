package cmd

import "testing"

func TestNewPgLoginInput(t *testing.T) {
	pw := newPgLoginInput("app", "password", []byte("s3cr3t"))
	if pw.GetRole() != "app" || pw.GetPassword().GetNewValue() == nil {
		t.Errorf("password login = %+v", pw)
	}
	if string(pw.GetPassword().GetNewValue()) != "s3cr3t" {
		t.Error("password value not carried")
	}
	m := newPgLoginInput("mtlsuser", "mtls", nil)
	if m.GetRole() != "mtlsuser" || m.GetMtls() == nil {
		t.Errorf("mtls login = %+v", m)
	}
}

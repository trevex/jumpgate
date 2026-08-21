package auth

import (
	"net/http"
	"testing"
)

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name           string
		headers        map[string]string
		wantRaw        string
		wantFromCookie bool
	}{
		{
			name:           "bearer only",
			headers:        map[string]string{"Authorization": "Bearer mytoken"},
			wantRaw:        "mytoken",
			wantFromCookie: false,
		},
		{
			name: "bearer wins over cookie",
			headers: map[string]string{
				"Authorization": "Bearer bearertok",
				"Cookie":        "jumpgate_session=cookietok",
			},
			wantRaw:        "bearertok",
			wantFromCookie: false,
		},
		{
			name:           "cookie only",
			headers:        map[string]string{"Cookie": "jumpgate_session=cookietok"},
			wantRaw:        "cookietok",
			wantFromCookie: true,
		},
		{
			name:           "cookie among others",
			headers:        map[string]string{"Cookie": "foo=1; jumpgate_session=tok; bar=2"},
			wantRaw:        "tok",
			wantFromCookie: true,
		},
		{
			name:    "none",
			headers: map[string]string{},
			wantRaw: "",
		},
		{
			name: "empty bearer falls through to cookie",
			headers: map[string]string{
				"Authorization": "Bearer ",
				"Cookie":        "jumpgate_session=cookietok",
			},
			wantRaw:        "cookietok",
			wantFromCookie: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tc.headers {
				h.Set(k, v)
			}
			raw, fromCookie := extractToken(h)
			if raw != tc.wantRaw {
				t.Errorf("raw: got %q, want %q", raw, tc.wantRaw)
			}
			if fromCookie != tc.wantFromCookie {
				t.Errorf("fromCookie: got %v, want %v", fromCookie, tc.wantFromCookie)
			}
		})
	}
}

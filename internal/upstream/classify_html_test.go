package upstream

import (
	"crypto/x509"
	"errors"
	"net/http"
	"testing"
)

func TestClassifyHTML401NotTerminal(t *testing.T) {
	html := "<html><head><title>401</title></head><body>proxy auth required: 12153 rate limit session expired</body></html>"
	if got := Classify(http.StatusUnauthorized, html); got != ErrClient {
		t.Fatalf("HTML 401 from a middle layer = %v, want ErrClient (rotate without penalty)", got)
	}
	jsonish := `{"code":12153,"msg":"session invalid, rate limit"}`
	if got := Classify(http.StatusUnauthorized, jsonish); got != ErrSessionDead {
		t.Fatalf("JSON 12153 401 = %v, want ErrSessionDead", got)
	}
	// HTML 403 without envelope still routes to the WAF branch, not account-fault.
	if got := Classify(http.StatusForbidden, "<html>blocked 11140 request illegal</html>"); got != ErrWafBlock {
		t.Fatalf("HTML 403 = %v, want ErrWafBlock", got)
	}
}

func TestLooksLikeHTMLPage(t *testing.T) {
	cases := map[string]bool{
		"<html>x":       true,
		"  <!doctype X": true,
		`{"code":0}`:    false,
		"":              false,
		"plain text":    false,
	}
	for body, want := range cases {
		if got := looksLikeHTMLPage(body); got != want {
			t.Fatalf("looksLikeHTMLPage(%q) = %v, want %v", body, got, want)
		}
	}
}

// 证书校验失败族识别（server 侧 isCertVerificationFailure 的错误形态来源）。
func TestX509ErrorsAsChain(t *testing.T) {
	wrapped := errors.Join(errors.New("Get \"https://x\": "), x509.UnknownAuthorityError{})
	var uax x509.UnknownAuthorityError
	if !errors.As(wrapped, &uax) {
		t.Fatal("errors.As must unwrap x509.UnknownAuthorityError from a joined chain")
	}
}

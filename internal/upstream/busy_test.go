package upstream

import (
	"net/http"
	"testing"
	"time"
)

func TestModelBusyClassification(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   ErrKind
	}{
		{429, `{"code":6021,"msg":"queue.full.title"}`, ErrModelBusy},
		{503, `{"error":{"code":"14003","msg":"too many requests","displayMsg":{"en":"Model busy. Please retry later"}}}`, ErrModelBusy},
		{200, `{"error":{"code":6021,"message":"queue.full.title"}}`, ErrModelBusy},
		{429, `{"code":6004,"msg":"queue.full.title"}`, ErrSoftRate},
		{429, `{"code":6021,"msg":"something else"}`, ErrSoftRate},
		{429, `{"requestId":"6021","msg":"queue.full.title"}`, ErrSoftRate},
		{200, `{"choices":[{"delta":{"content":"queue.full.title"}}],"code":6021,"msg":"queue.full.title"}`, ErrNone},
		{402, `{"code":6021,"msg":"queue.full.title"}`, ErrHardCredit},
		{429, `{"code":6021,"msg":"queue.full.title","error":{"code":12153}}`, ErrSessionDead},
		{429, `{"code":6021,"msg":"queue.full.title request illegal"}`, ErrAccountFault},
		{429, `<html>6021 queue.full.title</html>`, ErrSoftRate},
	} {
		if got := Classify(tc.status, tc.body); got != tc.want {
			t.Errorf("%d %s: %s want %s", tc.status, tc.body, got, tc.want)
		}
	}
}
func TestBusyRetryHints(t *testing.T) {
	for _, tc := range []struct {
		body             string
		want             time.Duration
		present, allowed bool
	}{
		{`{"retry_policy":{"retry_after":13}}`, 13 * time.Second, true, true},
		{`{"error":{"retry_policy":{"retry_after":"20"}}}`, 20 * time.Second, true, true},
		{`{"retry_policy":{"retry_after":0}}`, time.Second, true, true},
		{`{"retry_policy":{"retry":false,"retry_after":13}}`, 13 * time.Second, true, false},
		{`{"retry_policy":{"retry_after":-1}}`, 0, false, true},
		{`{"retry_policy":{"retry_after":1.5}}`, 0, false, true},
		{`{"retry_policy":{"retry_after":null}}`, 0, false, true},
		{`{"retry_policy":{"retry_after":"99999999999999999999"}}`, 0, false, true},
	} {
		d, p, a := ParseBusyRetryAfter(tc.body)
		if d != tc.want || p != tc.present || a != tc.allowed {
			t.Errorf("%s => %v %v %v", tc.body, d, p, a)
		}
	}
	h := http.Header{"Retry-After": []string{"20"}, "Retry-After-Ms": []string{"21000"}}
	e := NewModelBusyError(429, `{"retry_policy":{"retry_after":13}}`, h)
	if e.RetryAfter != 21*time.Second {
		t.Fatalf("max hint=%v", e.RetryAfter)
	}
	h.Set("Retry-After", time.Now().Add(time.Minute).UTC().Format(http.TimeFormat))
	if e = NewModelBusyError(429, `{}`, h); e.RetryAfter < 58*time.Second {
		t.Fatal(e.RetryAfter)
	}
}

func TestBusyFirstEventSafety(t *testing.T) {
	busy := "data: {\"error\":{\"code\":6021,\"message\":\"queue.full.title\",\"retry_policy\":{\"retry_after\":13}}}\n\n"
	role := "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n"
	for _, tc := range []struct {
		data string
		want bool
	}{
		{": ping\r\n\r\n" + busy, true}, {busy + "data: [DONE]\n\n", true}, {role + busy, false}, {busy + role, false}, {busy + "data: {\"choices\":", false}, {"data: [DONE]\n\n" + busy, false},
	} {
		e := BusyFirstEvent([]byte(tc.data), nil)
		if (e != nil) != tc.want {
			t.Fatalf("unsafe classification %q: %v", tc.data, e)
		}
		if e != nil && e.RetryAfter != 13*time.Second {
			t.Fatal(e.RetryAfter)
		}
	}
}

func TestBusyLongHeadersAndMalformedEnvelopes(t *testing.T) {
	e := NewModelBusyError(429, `{}`, http.Header{"Retry-After-Ms": []string{"10800000"}})
	if e.RetryAfter != 3*time.Hour {
		t.Fatal("long hint lost", e.RetryAfter)
	}
	if IsModelBusy(429, `{"code":6021,"msg":"queue.full.title"} garbage`) {
		t.Fatal("accepted malformed envelope")
	}
	if AcceptedChatEvent([]byte("data: {\"choices\":[],\"usage\":null}\n\n")) || AcceptedChatEvent([]byte("data: [DONE]\n\n")) || AcceptedChatEvent([]byte("data: {\"error\":{\"code\":6004}}\n\n")) {
		t.Fatal("error/done counted as generation")
	}
}

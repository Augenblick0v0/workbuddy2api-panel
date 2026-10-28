package upstream

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// busyNodes deliberately limits business envelopes to root/error. IDs and user
// generated text must never become routing instructions.
func busyNodes(body string) []map[string]any {
	var root map[string]any
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	if dec.Decode(&root) != nil || root == nil {
		return nil
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil
	}
	if _, ok := root["choices"]; ok {
		return nil
	}
	nodes := []map[string]any{root}
	if inner, ok := root["error"].(map[string]any); ok {
		nodes = append(nodes, inner)
	}
	return nodes
}

func IsModelBusy(status int, body string) bool {
	if status != 429 && status != 503 && status != 200 {
		return false
	}
	nodes := busyNodes(body)
	// A conflicting quota code remains the authoritative classification.
	for _, n := range nodes {
		if fmt.Sprint(n["code"]) == "6004" {
			return false
		}
	}
	for _, n := range nodes {
		code := fmt.Sprint(n["code"])
		for _, key := range []string{"msg", "message"} {
			msg, _ := n[key].(string)
			if code == "6021" && msg == "queue.full.title" {
				return true
			}
			if code == "14003" && strings.Contains(strings.ToLower(msg), "model busy") {
				return true
			}
		}
		display, _ := n["displayMsg"].(map[string]any)
		en, _ := display["en"].(string)
		if code == "14003" && strings.Contains(strings.ToLower(en), "model busy") {
			return true
		}
	}
	return false
}

func busySeconds(v any) (time.Duration, bool) {
	var s string
	switch v := v.(type) {
	case json.Number:
		s = v.String()
	case string:
		s = v
	default:
		return 0, false
	}
	if !isAllDigits(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > int64((time.Duration(1<<63-1))/time.Second) {
		return 0, false
	}
	if n == 0 {
		n = 1
	}
	return time.Duration(n) * time.Second, true
}

func ParseBusyRetryAfter(body string) (delay time.Duration, present, retryAllowed bool) {
	retryAllowed = true
	for _, n := range busyNodes(body) {
		policy, _ := n["retry_policy"].(map[string]any)
		if retry, ok := policy["retry"].(bool); ok && !retry {
			retryAllowed = false
		}
		if d, ok := busySeconds(policy["retry_after"]); ok {
			present = true
			if d > delay {
				delay = d
			}
		}
	}
	return
}

// NewModelBusyError retains the longest valid upstream hint. It does not cap a
// hint to our retry budget: doing so would send a request earlier than asked.
func NewModelBusyError(status int, body string, h http.Header) *Error {
	d, _, allowed := ParseBusyRetryAfter(body)
	source := "default"
	if d > 0 {
		source = "body"
	}
	choose := func(v time.Duration, s string) {
		if v > d {
			d = v
			source = s
		}
	}
	for _, name := range retryAfterHeaderCandidates {
		v := strings.TrimSpace(h.Get(name))
		if name == "Retry-After" {
			if n, ok := busySeconds(v); ok {
				choose(n, "header")
			} else if at, err := http.ParseTime(v); err == nil {
				n := time.Until(at)
				if n < time.Second {
					n = time.Second
				}
				choose(n, "http-date")
			}
		} else if isAllDigits(v) {
			if n, ok := busyHeaderNumber(v, name); ok && n > 0 {
				choose(n, "header")
			}
		}
	}
	return &Error{Kind: ErrModelBusy, Status: status, Msg: body, RetryAfter: d, BusyRetryAllowed: &allowed, RetryAfterSource: source}
}

func busyHeaderNumber(v, name string) (time.Duration, bool) {
	if name == "Retry-After-Ms" {
		n, e := strconv.ParseInt(v, 10, 64)
		if e != nil || n > int64(time.Duration(1<<63-1)/time.Millisecond) {
			return 0, false
		}
		d := time.Duration(n) * time.Millisecond
		if d < time.Second {
			d = time.Second
		}
		return d, true
	}
	d, ok := parseRetryNumber(v, name)
	if ok && d > 0 && d < time.Second {
		d = time.Second
	}
	return d, ok
}

// ModelBusyCode returns only the recognized business code, never raw error text.
func ModelBusyCode(body string) string {
	for _, n := range busyNodes(body) {
		if code := fmt.Sprint(n["code"]); code == "6021" || code == "14003" {
			return code
		}
	}
	return "unknown"
}

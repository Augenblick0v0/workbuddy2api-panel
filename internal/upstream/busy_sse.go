package upstream

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type chatReadCloser struct {
	io.ReadCloser
	headers http.Header
}

func BusyRetryHeaders(rc io.ReadCloser) http.Header {
	if r, ok := rc.(*chatReadCloser); ok {
		return r.headers
	}
	return nil
}

// BusyFirstEvent examines every complete event already read, in wire order.
// Any generated/unknown event or trailing partial data makes replay unsafe.
func BusyFirstEvent(prefix []byte, headers http.Header) *Error {
	normalized := bytes.ReplaceAll(prefix, []byte("\r\n"), []byte("\n"))
	events := bytes.Split(normalized, []byte("\n\n"))
	var result *Error
	for i, event := range events {
		var lines []string
		for _, line := range strings.Split(string(event), "\n") {
			if strings.HasPrefix(line, "data:") {
				lines = append(lines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
		}
		if len(lines) == 0 {
			continue
		}
		if i == len(events)-1 {
			return nil
		} // incomplete event
		payload := strings.Join(lines, "\n")
		if payload == "[DONE]" {
			if result == nil {
				return nil
			}
			continue
		}
		if Classify(200, payload) != ErrModelBusy {
			return nil
		}
		candidate := NewModelBusyError(429, payload, headers)
		if result == nil {
			result = candidate
		} else {
			if candidate.RetryAfter > result.RetryAfter {
				result.RetryAfter = candidate.RetryAfter
				result.RetryAfterSource = candidate.RetryAfterSource
			}
			if !*candidate.BusyRetryAllowed {
				result.BusyRetryAllowed = candidate.BusyRetryAllowed
			}
		}
	}
	return result
}

// AcceptedChatEvent only accepts generated chat/usage events, never errors or DONE.
func AcceptedChatEvent(prefix []byte) bool {
	normalized := bytes.ReplaceAll(prefix, []byte("\r\n"), []byte("\n"))
	events := bytes.Split(normalized, []byte("\n\n"))
	for _, event := range events[:len(events)-1] {
		var lines []string
		for _, line := range strings.Split(string(event), "\n") {
			if strings.HasPrefix(line, "data:") {
				lines = append(lines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
		var node map[string]json.RawMessage
		if json.Unmarshal([]byte(strings.Join(lines, "\n")), &node) != nil {
			continue
		}
		if _, bad := node["error"]; bad {
			continue
		}
		var choices []struct {
			Delta   map[string]any `json:"delta"`
			Message map[string]any `json:"message"`
		}
		json.Unmarshal(node["choices"], &choices)
		for _, choice := range choices {
			for _, message := range []map[string]any{choice.Delta, choice.Message} {
				for _, key := range []string{"role", "reasoning_content", "content"} {
					if _, ok := message[key].(string); ok {
						return true
					}
				}
				if calls, ok := message["tool_calls"].([]any); ok && len(calls) > 0 {
					return true
				}
			}
		}
		var usage map[string]any
		if json.Unmarshal(node["usage"], &usage) == nil && len(usage) > 0 {
			return true
		}
	}
	return false
}

type acceptedEventReader struct {
	io.ReadCloser
	pending []byte
	accept  func()
}

func ObserveAcceptedChatEvent(rc io.ReadCloser, accept func()) io.ReadCloser {
	return &acceptedEventReader{ReadCloser: rc, accept: accept}
}
func (r *acceptedEventReader) Read(p []byte) (int, error) {
	n, e := r.ReadCloser.Read(p)
	if r.accept != nil && n > 0 {
		r.pending = append(r.pending, p[:n]...)
		if AcceptedChatEvent(r.pending) {
			r.accept()
			r.accept = nil
			r.pending = nil
		} else if len(r.pending) > 1<<20 {
			r.pending = nil
		}
	}
	return n, e
}

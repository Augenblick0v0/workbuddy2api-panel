package egress

// ValidProtocol checks the supported transport scheme and protocol-specific
// credential limits. SOCKS5 auth length fields are single-byte octet counts.
func ValidProtocol(scheme, username, password string) bool {
	switch scheme {
	case "http", "https":
		return true
	case "socks5", "socks5h":
		return len(username) <= 255 && len(password) <= 255 && (username != "" || password == "")
	default:
		return false
	}
}

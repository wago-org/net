// Package dnsname validates and normalizes bounded ASCII DNS names shared by
// namespace, policy, and ABI layers.
package dnsname

import "net/netip"

// MaxLength is the maximum textual DNS name length without a trailing dot.
const MaxLength = 253

// ValidCanonical reports whether name is a lowercase ASCII DNS name without a
// trailing dot. IP literals and labels with invalid length or hyphen placement
// are rejected.
func ValidCanonical(name string) bool {
	return validString(name, len(name), true)
}

// ValidCanonicalBytes is the byte-slice equivalent of ValidCanonical. It lets
// fixed-width decoders validate guest memory before allocating the returned
// string.
func ValidCanonicalBytes(name []byte) bool {
	return validBytes(name, len(name), true)
}

// Normalize validates name case-insensitively, removes one optional trailing
// dot, and returns lowercase ASCII. Already-canonical input is returned without
// allocation.
func Normalize(name string) (string, bool) {
	length := len(name)
	if length != 0 && name[length-1] == '.' {
		length--
	}
	if !validString(name, length, false) {
		return "", false
	}

	hasUpper := false
	for i := 0; i < length; i++ {
		if name[i] >= 'A' && name[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return name[:length], true
	}

	normalized := make([]byte, length)
	for i := range normalized {
		value := name[i]
		if value >= 'A' && value <= 'Z' {
			value += 'a' - 'A'
		}
		normalized[i] = value
	}
	return string(normalized), true
}

func validString(name string, length int, canonical bool) bool {
	if length <= 0 || length > MaxLength || length > len(name) {
		return false
	}
	labelLength := 0
	allNumeric := true
	for i := 0; i < length; i++ {
		value := name[i]
		if value == '.' {
			if labelLength == 0 || labelLength > 63 || name[i-1] == '-' {
				return false
			}
			labelLength = 0
			continue
		}
		if labelLength == 0 && value == '-' {
			return false
		}
		if value >= 'A' && value <= 'Z' {
			if canonical {
				return false
			}
			value += 'a' - 'A'
		}
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-' {
			return false
		}
		if value < '0' || value > '9' {
			allNumeric = false
		}
		labelLength++
		if labelLength > 63 {
			return false
		}
	}
	if labelLength == 0 || name[length-1] == '-' {
		return false
	}
	return !allNumeric || !isIPLiteral(name[:length])
}

func validBytes(name []byte, length int, canonical bool) bool {
	if length <= 0 || length > MaxLength || length > len(name) {
		return false
	}
	labelLength := 0
	allNumeric := true
	for i := 0; i < length; i++ {
		value := name[i]
		if value == '.' {
			if labelLength == 0 || labelLength > 63 || name[i-1] == '-' {
				return false
			}
			labelLength = 0
			continue
		}
		if labelLength == 0 && value == '-' {
			return false
		}
		if value >= 'A' && value <= 'Z' {
			if canonical {
				return false
			}
			value += 'a' - 'A'
		}
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-' {
			return false
		}
		if value < '0' || value > '9' {
			allNumeric = false
		}
		labelLength++
		if labelLength > 63 {
			return false
		}
	}
	if labelLength == 0 || name[length-1] == '-' {
		return false
	}
	if !allNumeric {
		return true
	}
	return !isIPLiteralBytes(name[:length])
}

func isIPLiteral(name string) bool {
	address, err := netip.ParseAddr(name)
	return err == nil && address.IsValid()
}

func isIPLiteralBytes(name []byte) bool {
	parts := 0
	start := 0
	value := 0
	for i := 0; i <= len(name); i++ {
		if i != len(name) && name[i] != '.' {
			value = value*10 + int(name[i]-'0')
			if value > 255 {
				return false
			}
			continue
		}
		if i == start || i-start > 3 || i-start > 1 && name[start] == '0' {
			return false
		}
		parts++
		start = i + 1
		value = 0
	}
	return parts == 4
}

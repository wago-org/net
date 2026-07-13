// Package mdnsname validates the bounded lowercase ASCII DNS-SD names exposed
// by the mDNS module. Underscores are accepted for service labels; spaces,
// escapes, wildcards, and non-ASCII labels are intentionally outside ABI v1.
package mdnsname

import "net/netip"

const MaxLength = 253

func ValidCanonical(name string) bool { return valid(name, len(name), true) }

func ValidCanonicalBytes(name []byte) bool { return validBytes(name, len(name), true) }

func Normalize(name string) (string, bool) {
	length := len(name)
	if length != 0 && name[length-1] == '.' {
		length--
	}
	if !valid(name, length, false) {
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
	out := make([]byte, length)
	for i := range out {
		value := name[i]
		if value >= 'A' && value <= 'Z' {
			value += 'a' - 'A'
		}
		out[i] = value
	}
	return string(out), true
}

func valid(name string, length int, canonical bool) bool {
	if length <= 0 || length > MaxLength || length > len(name) {
		return false
	}
	label := 0
	for i := 0; i < length; i++ {
		value := name[i]
		if value == '.' {
			if label == 0 || label > 63 || name[i-1] == '-' {
				return false
			}
			label = 0
			continue
		}
		if label == 0 && value == '-' {
			return false
		}
		if value >= 'A' && value <= 'Z' {
			if canonical {
				return false
			}
			value += 'a' - 'A'
		}
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-' && value != '_' {
			return false
		}
		label++
		if label > 63 {
			return false
		}
	}
	if label == 0 || name[length-1] == '-' {
		return false
	}
	_, err := netip.ParseAddr(name[:length])
	return err != nil
}

func validBytes(name []byte, length int, canonical bool) bool {
	if length > len(name) {
		return false
	}
	return valid(string(name[:length]), length, canonical)
}

// Package mdnsname validates the bounded lowercase ASCII DNS-SD names exposed
// by the mDNS module. Underscores are accepted for service labels; spaces,
// escapes, wildcards, and non-ASCII labels are intentionally outside ABI v1.
package mdnsname

const MaxLength = 253

func ValidCanonical(name string) bool { return validString(name, len(name), true) }

func ValidCanonicalBytes(name []byte) bool { return validBytes(name, len(name), true) }

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
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-' && value != '_' {
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
	return !allNumeric || !isIPv4LiteralString(name[:length])
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
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-' && value != '_' {
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
	return !allNumeric || !isIPv4LiteralBytes(name[:length])
}

func isIPv4LiteralString(name string) bool {
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

func isIPv4LiteralBytes(name []byte) bool {
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

// Package checked provides allocation-free integer arithmetic used by bounded
// protocol configuration validators.
package checked

// AddUint64 returns left+right and false on overflow.
func AddUint64(left, right uint64) (uint64, bool) {
	sum := left + right
	return sum, sum >= left
}

// MultiplyUint64 returns left*right and false on overflow.
func MultiplyUint64(left, right uint64) (uint64, bool) {
	if left == 0 || right == 0 {
		return 0, true
	}
	if left > ^uint64(0)/right {
		return 0, false
	}
	return left * right, true
}

// Uint64ToInt returns value as int only when it fits maxIntValue. Supplying an
// explicit maximum permits architecture-independent 32-bit validation tests.
func Uint64ToInt(value, maxIntValue uint64) (int, bool) {
	if value > maxIntValue {
		return 0, false
	}
	return int(value), true
}

// MaxInt returns the current target architecture's maximum int as uint64.
func MaxInt() uint64 { return uint64(^uint(0) >> 1) }

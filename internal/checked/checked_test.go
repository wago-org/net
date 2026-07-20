package checked

import "testing"

func TestUint64ArithmeticOverflowAndIntBounds(t *testing.T) {
	if sum, ok := AddUint64(^uint64(0), 1); ok || sum != 0 {
		t.Fatalf("overflowing add = %d, %v", sum, ok)
	}
	if product, ok := MultiplyUint64(^uint64(0), 2); ok || product != 0 {
		t.Fatalf("overflowing multiply = %d, %v", product, ok)
	}
	if sum, ok := AddUint64(40, 2); !ok || sum != 42 {
		t.Fatalf("valid add = %d, %v", sum, ok)
	}
	if product, ok := MultiplyUint64(6, 7); !ok || product != 42 {
		t.Fatalf("valid multiply = %d, %v", product, ok)
	}
	max32 := uint64(^uint32(0) >> 1)
	if _, ok := Uint64ToInt(max32, max32); !ok {
		t.Fatal("32-bit maximum rejected")
	}
	if _, ok := Uint64ToInt(max32+1, max32); ok {
		t.Fatal("32-bit overflow accepted")
	}
}

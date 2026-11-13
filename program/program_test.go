package program

import "testing"

func TestRejectsPartialPacket(t *testing.T) {
	if _, err := Parse([]byte{0x47}); err == nil {
		t.Fatal("expected packet size error")
	}
}

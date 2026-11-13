package program

import (
	"encoding/binary"
	"testing"
)

// ---- sample builders -----------------------------------------------------

// makePAT builds a well-formed single-program PAT section for the given
// program number and PMT PID.
func makePAT(programNumber, pmtPID int) []byte {
	sectionLength := 13 // fixed header 8 + one program loop entry 4 + CRC 4 - 3
	section := make([]byte, 3+sectionLength)
	section[0] = patTableID
	section[1] = byte(sectionLength>>8) & 0x0f
	section[2] = byte(sectionLength)
	binary.BigEndian.PutUint16(section[3:5], 1) // transport stream id
	section[5] = 0xc1                           // version 0, current=1
	section[6] = 0                              // section number
	section[7] = 0                              // last section number
	binary.BigEndian.PutUint16(section[8:10], uint16(programNumber))
	section[10] = 0xe0 | byte(pmtPID>>8)
	section[11] = byte(pmtPID)
	return section
}

// makePMT builds a well-formed PMT section carrying the given stream
// (streamType, PID) entries, plus the PCR PID.
func makePMT(programNumber, pcrPID int, streams []Stream) []byte {
	sectionLength := 13 + len(streams)*5 // header 9 + program info 0 + entries + CRC 4
	section := make([]byte, 3+sectionLength)
	section[0] = pmtTableID
	section[1] = byte(sectionLength>>8) & 0x0f
	section[2] = byte(sectionLength)
	binary.BigEndian.PutUint16(section[3:5], uint16(programNumber))
	section[5] = 0xc1
	section[6] = 0
	section[7] = 0
	section[8] = 0xe0 | byte(pcrPID>>8)
	section[9] = byte(pcrPID)
	section[10] = 0xf0 // program info length 0
	section[11] = 0
	pos := 12
	for _, s := range streams {
		kind := byte(0x06) // default: unknown/private -> "other"
		switch s.Kind {
		case "video":
			kind = 0x1b
		case "audio":
			kind = 0x0f
		}
		section[pos] = kind
		section[pos+1] = 0xe0 | byte(s.PID>>8)
		section[pos+2] = byte(s.PID)
		section[pos+3] = 0xf0 // ES info length 0
		section[pos+4] = 0
		pos += 5
	}
	return section
}

// tsPacket wraps one payload in a transport packet. Slack between the payload
// and the 188-byte packet end is absorbed by an adaptation field, so a short
// payload never leaves 0xff bytes where section bytes are expected.
func tsPacket(pid int, pusi bool, payload []byte) []byte {
	packet := make([]byte, 188)
	for i := range packet {
		packet[i] = 0xff
	}
	packet[0] = syncByte
	packet[1] = byte(pid >> 8)
	if pusi {
		packet[1] |= 0x40
	}
	packet[2] = byte(pid)
	pad := 184 - len(payload)
	if pad > 0 {
		packet[3] = 0x31 // adaptation field + payload
		packet[4] = byte(pad - 1)
		start := 5 + pad - 1
		copy(packet[start:], payload)
	} else {
		packet[3] = 0x10 // payload only
		copy(packet[4:], payload)
	}
	return packet
}

// tsPacketFragment builds a continuation packet carrying only the given
// section fragment. Unused packet space is absorbed by an adaptation field,
// so the payload contains pure section bytes with no 0xff stuffing (which is
// only legal after a complete section).
func tsPacketFragment(pid int, fragment []byte) []byte {
	packet := make([]byte, 188)
	for i := range packet {
		packet[i] = 0xff
	}
	packet[0] = syncByte
	packet[1] = byte(pid >> 8) // PUSI clear: continuation
	packet[2] = byte(pid)
	// Adaptation field of the exact size needed to push the fragment to the
	// packet tail. adaptation_length field itself counts from byte 5.
	payloadCap := 184
	pad := payloadCap - len(fragment)
	if pad > 0 {
		packet[3] = 0x31 // adaptation + payload
		packet[4] = byte(pad - 1)
		start := 5 + pad - 1
		copy(packet[start:], fragment)
	} else {
		packet[3] = 0x10
		copy(packet[4:], fragment)
	}
	return packet
}

// tsPacketAdaptation puts a payload after an adaptation field of the given
// total length, so the payload start moves inside the packet.
func tsPacketAdaptation(pid int, pusi bool, adaptationLen int, payload []byte) []byte {
	packet := make([]byte, 188)
	for i := range packet {
		packet[i] = 0xff
	}
	packet[0] = syncByte
	packet[1] = byte(pid >> 8)
	if pusi {
		packet[1] |= 0x40
	}
	packet[2] = byte(pid)
	packet[3] = 0x31 // adaptation + payload
	packet[4] = byte(adaptationLen)
	// adaptation field bytes default to 0xff stuffing; flags byte is zero
	start := 5 + adaptationLen
	copy(packet[start:], payload)
	return packet
}

func pointerPayload(section []byte, pointer int) []byte {
	payload := make([]byte, 1+pointer+len(section))
	payload[0] = byte(pointer)
	for i := 0; i < pointer; i++ {
		payload[1+i] = 0xaa
	}
	copy(payload[1+pointer:], section)
	return payload
}

// splitPackets delivers one section across several packets on a PID. Only
// the first packet carries PUSI and a pointer field; continuation packets
// carry pure section fragments. Every fragment shorter than the payload
// capacity absorbs the slack in an adaptation field, so no packet emits 0xff
// stuffing after an incomplete fragment.
func splitPackets(pid int, section []byte, firstChunk int) [][]byte {
	var packets [][]byte
	first := make([]byte, 1+firstChunk)
	first[0] = 0 // pointer field: section starts right after it
	copy(first[1:], section[:firstChunk])
	packets = append(packets, tsPacketStuffed(pid, first))
	rest := section[firstChunk:]
	for len(rest) > 0 {
		n := 47
		if n > len(rest) {
			n = len(rest)
		}
		packets = append(packets, tsPacketFragment(pid, rest[:n]))
		rest = rest[n:]
	}
	return packets
}

// tsPacketStuffed builds a PUSI packet whose payload is exactly payload,
// moving any unused packet space into an adaptation field.
func tsPacketStuffed(pid int, payload []byte) []byte {
	packet := make([]byte, 188)
	for i := range packet {
		packet[i] = 0xff
	}
	packet[0] = syncByte
	packet[1] = byte(pid>>8) | 0x40 // PUSI set
	packet[2] = byte(pid)
	pad := 184 - len(payload)
	if pad > 0 {
		packet[3] = 0x31 // adaptation + payload
		packet[4] = byte(pad - 1)
		start := 5 + pad - 1
		copy(packet[start:], payload)
	} else {
		packet[3] = 0x10
		copy(packet[4:], payload)
	}
	return packet
}

func flatten(packets ...[]byte) []byte {
	var out []byte
	for _, p := range packets {
		out = append(out, p...)
	}
	return out
}

// ---- tests ---------------------------------------------------------------

func TestRejectsPartialPacket(t *testing.T) {
	if _, err := Parse([]byte{0x47}); err == nil {
		t.Fatal("expected packet size error")
	}
}

func TestPointerFieldOffsets(t *testing.T) {
	pat := makePAT(1, 256)
	pmt := makePMT(1, 257, []Stream{
		{PID: 257, Kind: "video"},
		{PID: 258, Kind: "audio"},
	})
	for _, pointer := range []int{0, 1, 2, 7} {
		data := flatten(
			tsPacket(0, true, pointerPayload(pat, pointer)),
			tsPacket(256, true, pointerPayload(pmt, pointer)),
		)
		got, err := Parse(data)
		if err != nil {
			t.Fatalf("pointer=%d: unexpected error: %v", pointer, err)
		}
		if got.ProgramNumber != 1 || got.PMTPID != 256 || got.PCRPID != 257 {
			t.Fatalf("pointer=%d: mapping mismatch: %+v", pointer, got)
		}
		if len(got.Streams) != 2 ||
			got.Streams[0] != (Stream{PID: 257, Kind: "video"}) ||
			got.Streams[1] != (Stream{PID: 258, Kind: "audio"}) {
			t.Fatalf("pointer=%d: streams mismatch: %+v", pointer, got.Streams)
		}
		if got.Scanned != 2 {
			t.Fatalf("pointer=%d: scanned=%d, want 2", pointer, got.Scanned)
		}
	}
}

func TestAdaptationFieldWithPointer(t *testing.T) {
	pat := makePAT(1, 256)
	pmt := makePMT(1, 257, []Stream{{PID: 257, Kind: "video"}})
	data := flatten(
		tsPacketAdaptation(0, true, 6, pointerPayload(pat, 2)),
		tsPacketAdaptation(256, true, 10, pointerPayload(pmt, 3)),
	)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ProgramNumber != 1 || got.PMTPID != 256 || got.PCRPID != 257 {
		t.Fatalf("mapping mismatch: %+v", got)
	}
	if len(got.Streams) != 1 || got.Streams[0].PID != 257 {
		t.Fatalf("streams mismatch: %+v", got.Streams)
	}
}

func TestSectionSpanningPackets(t *testing.T) {
	pat := makePAT(1, 256)
	pmt := makePMT(1, 257, []Stream{
		{PID: 257, Kind: "video"},
		{PID: 258, Kind: "audio"},
		{PID: 300, Kind: "other"},
	})
	data := flatten(
		tsPacket(0, true, pointerPayload(pat, 0)),
		flatten(splitPackets(256, pmt, 30)...),
	)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ProgramNumber != 1 || got.PMTPID != 256 || got.PCRPID != 257 {
		t.Fatalf("mapping mismatch: %+v", got)
	}
	want := []Stream{
		{PID: 257, Kind: "video"},
		{PID: 258, Kind: "audio"},
		{PID: 300, Kind: "other"},
	}
	if len(got.Streams) != len(want) {
		t.Fatalf("streams mismatch: %+v", got.Streams)
	}
	for i := range want {
		if got.Streams[i] != want[i] {
			t.Fatalf("stream %d = %+v, want %+v", i, got.Streams[i], want[i])
		}
	}
}

func TestUnknownStreamTypeIsOther(t *testing.T) {
	pat := makePAT(7, 400)
	pmt := makePMT(7, 500, []Stream{
		{PID: 501, Kind: "other"},
		{PID: 502, Kind: "video"},
	})
	data := flatten(
		tsPacket(0, true, pointerPayload(pat, 0)),
		tsPacket(400, true, pointerPayload(pmt, 0)),
	)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ProgramNumber != 7 || got.PMTPID != 400 || got.PCRPID != 500 {
		t.Fatalf("mapping mismatch: %+v", got)
	}
	if got.Streams[0].Kind != "other" || got.Streams[1].Kind != "video" {
		t.Fatalf("kind classification mismatch: %+v", got.Streams)
	}
}

func TestNewSectionResetsIncompleteBuffer(t *testing.T) {
	pat := makePAT(1, 256)
	pmt := makePMT(1, 257, []Stream{{PID: 257, Kind: "video"}})

	// A PMT section that starts on PID 256 but never finishes (its declared
	// length exceeds what arrives), followed by a fresh, complete section on
	// the next PUSI. The reset must discard the orphaned fragment so it can
	// never pollute the new program.
	orphan := make([]byte, 10)
	orphan[0] = pmtTableID
	orphan[1] = 0x00
	orphan[2] = 100 // declares 100 bytes; far more than ever arrives
	data := flatten(
		tsPacket(0, true, pointerPayload(pat, 0)),
		tsPacketFragment(256, orphan),               // incomplete continuation
		tsPacket(256, true, pointerPayload(pmt, 0)), // PUSI resets the buffer
	)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Streams) != 1 || got.Streams[0] != (Stream{PID: 257, Kind: "video"}) {
		t.Fatalf("orphaned section polluted the result: %+v", got.Streams)
	}
	if got.PCRPID != 257 {
		t.Fatalf("pcr pid mismatch: %+v", got)
	}
}

func TestPIDIsolation(t *testing.T) {
	pat := makePAT(1, 256)
	pmt := makePMT(1, 257, []Stream{{PID: 257, Kind: "audio"}})
	// Interleave unrelated PIDs (including null PID 0x1fff) between tables.
	// 0x200 is deliberately distinct from the PAT PID 0 and PMT PID 256.
	noise1 := tsPacket(0x200, true, make([]byte, 60))
	noise2 := tsPacket(0x1fff, false, make([]byte, 40))
	data := flatten(
		tsPacket(0, true, pointerPayload(pat, 2)),
		noise1,
		noise2,
		tsPacket(256, true, pointerPayload(pmt, 2)),
	)
	// Sanity check: the four packets keep their distinct PIDs in order.
	wantPIDs := []int{0, 0x200, 0x1fff, 256}
	for i, want := range wantPIDs {
		if got := packetPID(data[i*188:]); got != want {
			t.Fatalf("packet %d pid=%d, want %d", i, got, want)
		}
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.PMTPID != 256 || got.PCRPID != 257 || len(got.Streams) != 1 {
		t.Fatalf("isolation broken: %+v", got)
	}
	if got.Scanned != 4 {
		t.Fatalf("scanned=%d, want 4 (one count per packet, single pass)", got.Scanned)
	}
}

func TestTruncatedSectionHeaderErrors(t *testing.T) {
	pat := makePAT(1, 256)
	data := flatten(
		tsPacket(0, true, pointerPayload(pat, 0)),
		// PMT starts but its 3-byte header never fully arrives.
		tsPacket(256, true, pointerPayload([]byte{pmtTableID, 0x00}, 0)),
	)
	if _, err := Parse(data); err == nil {
		t.Fatal("expected error for truncated section header at end of stream")
	}
}

func TestPointerBeyondPayloadErrors(t *testing.T) {
	// A full 184-byte payload whose pointer field points past its own end.
	payload := make([]byte, 184)
	payload[0] = 200
	data := tsPacket(0, true, payload)
	if _, err := Parse(data); err == nil {
		t.Fatal("expected error when pointer field exceeds payload bounds")
	}
}

func TestRepeatedPMTReplacesStreams(t *testing.T) {
	pat := makePAT(1, 256)
	first := makePMT(1, 257, []Stream{{PID: 257, Kind: "video"}})
	second := makePMT(1, 258, []Stream{
		{PID: 258, Kind: "video"},
		{PID: 259, Kind: "audio"},
	})
	data := flatten(
		tsPacket(0, true, pointerPayload(pat, 0)),
		tsPacket(256, true, pointerPayload(first, 0)),
		tsPacket(256, true, pointerPayload(second, 0)),
	)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.PCRPID != 258 || len(got.Streams) != 2 {
		t.Fatalf("repeated PMT should replace, not append: %+v", got)
	}
}

func TestScannedCountsEveryPacketOnce(t *testing.T) {
	pat := makePAT(1, 256)
	pmt := makePMT(1, 257, []Stream{{PID: 257, Kind: "video"}})
	null := tsPacket(0x1fff, false, make([]byte, 50))
	data := flatten(
		null,
		tsPacket(0, true, pointerPayload(pat, 0)),
		null,
		tsPacket(256, true, pointerPayload(pmt, 0)),
		null,
	)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Scanned != 5 {
		t.Fatalf("scanned=%d, want 5", got.Scanned)
	}
}

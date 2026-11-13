package program

import "fmt"

const (
	patPID     = 0
	patTableID = 0x00
	pmtTableID = 0x02
	syncByte   = 0x47
	packetSize = 188
)

type Stream struct {
	PID  int    `json:"pid"`
	Kind string `json:"kind"`
}

type Result struct {
	ProgramNumber int      `json:"program_number"`
	PMTPID        int      `json:"pmt_pid"`
	PCRPID        int      `json:"pcr_pid"`
	Streams       []Stream `json:"streams"`
	Scanned       int      `json:"scanned"`
}

// packetPayload returns the payload area of a 188-byte transport stream
// packet, taking the optional adaptation field into account. It does not
// consume the pointer field, which only exists in packets that start a new
// section and is handled by the section reassembler.
func packetPayload(packet []byte) (payload []byte, pusi bool, ok bool) {
	if len(packet) != packetSize || packet[0] != syncByte {
		return nil, false, false
	}
	pusi = packet[1]&0x40 != 0
	control := (packet[3] >> 4) & 3
	if control == 0 || control == 2 {
		return nil, pusi, false // reserved, or adaptation field only
	}
	start := 4
	if control == 3 { // adaptation field followed by payload
		start = 5 + int(packet[4])
		if start > packetSize {
			return nil, pusi, false
		}
	}
	return packet[start:], pusi, true
}

func packetPID(packet []byte) int {
	return int(packet[1]&0x1f)<<8 | int(packet[2])
}

// Parse walks the transport stream once, packet by packet. It reassembles
// PAT/PMT sections (which may span several packets) per PID, so packet
// framing, continuity counters and unknown stream types can never leak data
// from one section or program into the next.
func Parse(data []byte) (Result, error) {
	if len(data)%packetSize != 0 {
		return Result{}, fmt.Errorf("transport stream length is not a multiple of 188")
	}
	result := Result{PMTPID: -1, PCRPID: -1}
	// One reassembly buffer per table-bearing PID; PUSI resets a buffer,
	// keeping sections on different PIDs fully isolated.
	buffers := make(map[int][]byte)

	for offset := 0; offset < len(data); offset += packetSize {
		result.Scanned++
		packet := data[offset : offset+packetSize]
		if packet[0] != syncByte {
			continue
		}
		currentPID := packetPID(packet)
		if currentPID != patPID && currentPID != result.PMTPID {
			continue
		}
		payload, pusi, ok := packetPayload(packet)
		if !ok {
			continue
		}

		buf := buffers[currentPID]
		if pusi {
			// First payload byte is the pointer field. Any bytes before the
			// section start belong to the previous section (or are stuffing);
			// the unfinished section, if any, is discarded here.
			if len(payload) == 0 {
				return Result{}, fmt.Errorf("payload unit start indicator set without pointer field on PID %d", currentPID)
			}
			pointer := int(payload[0])
			sectionStart := 1 + pointer
			if sectionStart > len(payload) {
				return Result{}, fmt.Errorf("pointer field %d exceeds payload bounds on PID %d", pointer, currentPID)
			}
			buf = append(buf[:0], payload[sectionStart:]...)
		} else {
			// Continuation packet: its whole payload extends the section.
			buf = append(buf, payload...)
		}

		var err error
		if currentPID == patPID {
			buf, err = consumeSections(buf, patTableID, true, &result)
		} else {
			buf, err = consumeSections(buf, pmtTableID, false, &result)
		}
		if err != nil {
			return Result{}, err
		}
		buffers[currentPID] = buf
	}

	for pid, buf := range buffers {
		if !hasSectionData(buf) {
			continue
		}
		var err error
		if pid == patPID {
			err = finalizeSection(buf, patTableID, true, &result)
		} else {
			err = finalizeSection(buf, pmtTableID, false, &result)
		}
		if err != nil {
			return Result{}, err
		}
	}
	return result, nil
}

// consumeSections removes every complete section from the head of buf.
// Sections are sliced exactly at their declared length, so parsing can never
// read past a section boundary. A head section whose declared length reaches
// beyond the buffered bytes is left in place for continuation packets (or,
// once the stream ends, for finalizeSection).
func consumeSections(buf []byte, tableID byte, isPAT bool, result *Result) ([]byte, error) {
	for len(buf) >= 3 {
		if buf[0] == 0xff { // table stuffing
			buf = buf[1:]
			continue
		}
		if buf[0] != tableID {
			return nil, fmt.Errorf("unexpected table_id %#x (want %#x)", buf[0], tableID)
		}
		sectionLength := int(buf[1]&0x0f)<<8 | int(buf[2])
		total := 3 + sectionLength
		if total > len(buf) {
			return buf, nil // wait for the rest of the section
		}
		var err error
		if isPAT {
			err = parsePAT(buf[:total], result)
		} else {
			err = parsePMT(buf[:total], result)
		}
		if err != nil {
			return nil, err
		}
		buf = buf[total:]
	}
	return buf, nil
}

// finalizeSection gives a section left incomplete at end of stream its last
// chance. A section whose header and inner entries are fully present is
// parsed; a header truncated mid-stream is a hard error, so half packets can
// never produce a half-built program.
func finalizeSection(buf []byte, tableID byte, isPAT bool, result *Result) error {
	if !hasSectionData(buf) {
		return nil
	}
	if len(buf) < 3 || (buf[0] != 0xff && buf[0] != tableID) {
		return fmt.Errorf("truncated section header at end of stream")
	}
	if buf[0] == 0xff {
		return nil
	}
	if isPAT {
		return parsePAT(buf, result)
	}
	return parsePMT(buf, result)
}

// parsePAT records the first program-to-PMT mapping. The PAT only maps
// programs to PMT PIDs; stream details come from the PMT.
func parsePAT(section []byte, result *Result) error {
	if len(section) < 8 {
		return fmt.Errorf("PAT section header is truncated")
	}
	length := int(section[1]&0x0f)<<8 | int(section[2])
	// Never walk past either the declared section end or the bytes on hand,
	// and reserve the trailing 4-byte CRC32 covered by section_length.
	end := 3 + length
	if end > len(section) {
		end = len(section)
	}
	limit := end - 4
	for pos := 8; pos+4 <= limit; pos += 4 {
		programNumber := int(section[pos])<<8 | int(section[pos+1])
		pmtPID := int(section[pos+2]&0x1f)<<8 | int(section[pos+3])
		if programNumber == 0 {
			continue // network PID entry, not a program
		}
		result.ProgramNumber = programNumber
		result.PMTPID = pmtPID
		break
	}
	return nil
}

// parsePMT extracts the PCR PID and every elementary stream. Streams are
// replaced wholesale on repeated sections, and unknown stream types are kept
// as "other" instead of being mistaken for audio or video.
func parsePMT(section []byte, result *Result) error {
	if len(section) < 12 {
		return fmt.Errorf("PMT section header is truncated")
	}
	length := int(section[1]&0x0f)<<8 | int(section[2])
	end := 3 + length
	if end > len(section) {
		end = len(section)
	}
	// Entries end where the 4-byte CRC32 begins.
	limit := end - 4
	pcrPID := int(section[8]&0x1f)<<8 | int(section[9])
	infoLength := int(section[10]&0x0f)<<8 | int(section[11])
	if 12+infoLength > limit {
		return fmt.Errorf("program info length exceeds PMT section bounds")
	}
	streams := make([]Stream, 0)
	pos := 12 + infoLength
	for pos+5 <= limit {
		streamType := section[pos]
		streamPID := int(section[pos+1]&0x1f)<<8 | int(section[pos+2])
		esInfoLength := int(section[pos+3]&0x0f)<<8 | int(section[pos+4])
		next := pos + 5 + esInfoLength
		if next > limit {
			return fmt.Errorf("elementary stream info exceeds PMT section bounds")
		}
		streams = append(streams, Stream{PID: streamPID, Kind: streamKind(streamType)})
		pos = next
	}
	result.PCRPID = pcrPID
	result.Streams = streams
	return nil
}

func streamKind(streamType byte) string {
	switch streamType {
	case 0x1b, 0x24: // H.264, H.265
		return "video"
	case 0x0f, 0x11, 0x81: // AAC ADTS, AAC LATM, AC-3
		return "audio"
	default:
		return "other"
	}
}

func hasSectionData(buf []byte) bool {
	for _, b := range buf {
		if b != 0xff {
			return true
		}
	}
	return false
}

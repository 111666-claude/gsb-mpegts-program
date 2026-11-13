package program

import "fmt"

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

func packetPayload(packet []byte) ([]byte, bool) {
	if len(packet) != 188 || packet[0] != 0x47 {
		return nil, false
	}
	control := (packet[3] >> 4) & 3
	if control == 2 || control == 0 {
		return nil, false
	}
	start := 4
	if control == 3 {
		start += 1 + int(packet[4])
	}
	if start >= len(packet) {
		return nil, false
	}
	return packet[start:], packet[1]&0x40 != 0
}

func pid(packet []byte) int { return int(packet[1]&0x1f)<<8 | int(packet[2]) }

func Parse(data []byte) (Result, error) {
	if len(data)%188 != 0 {
		return Result{}, fmt.Errorf("transport stream length is not a multiple of 188")
	}
	result := Result{PMTPID: -1, PCRPID: -1}
	for offset := 0; offset < len(data); offset += 188 {
		result.Scanned++
		packet := data[offset : offset+188]
		payload, start := packetPayload(packet)
		if payload == nil || !start {
			continue
		}
		currentPID := pid(packet)
		if currentPID == 0 {
			if len(payload) < 13 {
				continue
			}
			section := payload[1:]
			length := int(section[1]&0x0f)<<8 | int(section[2])
			if length+3 > len(section) {
				continue
			}
			result.ProgramNumber = int(section[8])<<8 | int(section[9])
			result.PMTPID = int(section[10]&0x1f)<<8 | int(section[11])
			continue
		}
		if currentPID != result.PMTPID || len(payload) < 13 {
			continue
		}
		section := payload[1:]
		length := int(section[1]&0x0f)<<8 | int(section[2])
		if length+3 > len(section) {
			continue
		}
		result.PCRPID = int(section[8]&0x1f)<<8 | int(section[9])
		infoLength := int(section[10]&0x0f)<<8 | int(section[11])
		pos := 12 + infoLength
		end := 3 + length - 4
		for pos+5 <= end && pos+5 <= len(section) {
			streamType := section[pos]
			streamPID := int(section[pos+1]&0x1f)<<8 | int(section[pos+2])
			esInfo := int(section[pos+3]&0x0f)<<8 | int(section[pos+4])
			kind := "other"
			if streamType == 0x1b || streamType == 0x24 {
				kind = "video"
			}
			if streamType == 0x0f || streamType == 0x11 || streamType == 0x81 {
				kind = "audio"
			}
			result.Streams = append(result.Streams, Stream{PID: streamPID, Kind: kind})
			pos += 5 + esInfo
		}
	}
	return result, nil
}

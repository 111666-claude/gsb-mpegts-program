package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"example.com/mpegtsprogram/program"
)

func packet(pid int, payloadStart bool, payload []byte) []byte {
	out := make([]byte, 188)
	for i := range out {
		out[i] = 0xff
	}
	out[0] = 0x47
	out[1] = byte(pid >> 8)
	if payloadStart {
		out[1] |= 0x40
	}
	out[2] = byte(pid)
	out[3] = 0x10
	copy(out[4:], payload)
	return out
}

func withPointer(section []byte, pointer int) []byte {
	payload := make([]byte, 1+pointer+len(section))
	payload[0] = byte(pointer)
	for i := 0; i < pointer; i++ {
		payload[1+i] = 0xaa
	}
	copy(payload[1+pointer:], section)
	return payload
}

func sampleTS(pointer int) []byte {
	pat := make([]byte, 16)
	pat[0] = 0
	pat[1] = 0
	pat[2] = 13
	binary.BigEndian.PutUint16(pat[8:10], 1)
	pat[10] = 0xe1
	pat[11] = 0x00
	pmt := make([]byte, 26)
	pmt[0] = 2
	pmt[1] = 0
	pmt[2] = 24
	binary.BigEndian.PutUint16(pmt[3:5], 1)
	pmt[8] = 0xe1
	pmt[9] = 0x01
	pmt[10] = 0xf0
	pmt[11] = 0
	pmt[12] = 0x1b
	pmt[13] = 0xe1
	pmt[14] = 0x01
	pmt[15] = 0xf0
	pmt[16] = 0
	pmt[17] = 0x0f
	pmt[18] = 0xe1
	pmt[19] = 0x02
	pmt[20] = 0xf0
	pmt[21] = 0
	return append(packet(0, true, withPointer(pat, pointer)), packet(256, true, withPointer(pmt, pointer))...)
}

func main() {
	sample := flag.String("sample", "av", "sample name")
	flag.Parse()
	if *sample != "av" && *sample != "pointer" {
		fmt.Fprintln(os.Stderr, "unknown sample")
		os.Exit(2)
	}
	pointer := 0
	if *sample == "pointer" {
		pointer = 2
	}
	result, err := program.Parse(sampleTS(pointer))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data, _ := json.Marshal(result)
	fmt.Println(string(data))
}

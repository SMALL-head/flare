package bpfgo

import (
	"bytes"
)

func GoString(data []int8) string {
	resB := make([]byte, len(data))
	for i, v := range data {
		resB[i] = byte(v)
	}
	return string(bytes.Split(resB, []byte("\x00"))[0])
}

// s不要用中文
func GoString2BpfCharArray16(s string) [16]int8 {
	if len(s) >= 16 {
		s = s[:15]
	}
	res := [16]int8{}
	for i := range s {
		res[i] = int8(s[i])
	}
	res[len(s)] = 0
	return res
}

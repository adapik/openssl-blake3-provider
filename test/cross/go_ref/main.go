package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"lukechampine.com/blake3"
)

func unhex(s string) []byte {
	if s == "-" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	mf, _ := os.Open(os.Args[1])
	bf, _ := os.Open(os.Args[2])
	sc := bufio.NewScanner(mf)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	idx := 0
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		mode := f[0]
		n, _ := strconv.Atoi(f[1])
		outlen, _ := strconv.Atoi(f[4])
		off, _ := strconv.ParseInt(f[5], 10, 64)
		data := make([]byte, n)
		bf.Seek(off, 0)
		if _, err := io.ReadFull(bf, data); err != nil && n > 0 {
			panic(err)
		}
		out := make([]byte, outlen)
		switch mode {
		case "hash":
			h := blake3.New(outlen, nil)
			h.Write(data)
			h.Sum(out[:0])
		case "keyed":
			h := blake3.New(outlen, unhex(f[2]))
			h.Write(data)
			h.Sum(out[:0])
		default:
			blake3.DeriveKey(out, string(unhex(f[3])), data)
		}
		fmt.Printf("%d %s\n", idx, hex.EncodeToString(out))
		idx++
	}
}

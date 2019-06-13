package ternary

import "bytes"

const (
	NUMBER_OF_TRITS_IN_A_BYTE  = 5
	NUMBER_OF_TRITS_IN_A_TRYTE = 3
)

var (
	TRYTES_TO_TRITS_MAP = map[rune][]int8{
		'9': Trits{0, 0, 0},
		'A': Trits{1, 0, 0},
		'B': Trits{-1, 1, 0},
		'C': Trits{0, 1, 0},
		'D': Trits{1, 1, 0},
		'E': Trits{-1, -1, 1},
		'F': Trits{0, -1, 1},
		'G': Trits{1, -1, 1},
		'H': Trits{-1, 0, 1},
		'I': Trits{0, 0, 1},
		'J': Trits{1, 0, 1},
		'K': Trits{-1, 1, 1},
		'L': Trits{0, 1, 1},
		'M': Trits{1, 1, 1},
		'N': Trits{-1, -1, -1},
		'O': Trits{0, -1, -1},
		'P': Trits{1, -1, -1},
		'Q': Trits{-1, 0, -1},
		'R': Trits{0, 0, -1},
		'S': Trits{1, 0, -1},
		'T': Trits{-1, 1, -1},
		'U': Trits{0, 1, -1},
		'V': Trits{1, 1, -1},
		'W': Trits{-1, -1, 0},
		'X': Trits{0, -1, 0},
		'Y': Trits{1, -1, 0},
		'Z': Trits{-1, 0, 0},
	}

	TRYTE_ALPHABET = []string{
		"9", "A", "B", "C", "D", "E", "F", "G", "H",
		"I", "J", "K", "L", "M", "N", "O", "P", "Q",
		"R", "S", "T", "U", "V", "W", "X", "Y", "Z",
	}

	BYTES_TO_TRITS = []Trit{
		0, 0, 0, 0, 0, 1, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, -1, -1,
		1, 0, 0, 0, -1, 1, 0, 0, 1, -1, 1, 0, 0, -1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0,
		0, -1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, -1, -1, -1, 1, 0, 0, -1, -1, 1, 0, 1,
		-1, -1, 1, 0, -1, 0, -1, 1, 0, 0, 0, -1, 1, 0, 1, 0, -1, 1, 0, -1, 1, -1, 1, 0, 0, 1, -1,
		1, 0, 1, 1, -1, 1, 0, -1, -1, 0, 1, 0, 0, -1, 0, 1, 0, 1, -1, 0, 1, 0, -1, 0, 0, 1, 0,
		0, 0, 0, 1, 0, 1, 0, 0, 1, 0, -1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, -1, -1,
		1, 1, 0, 0, -1, 1, 1, 0, 1, -1, 1, 1, 0, -1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1,
		0, -1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, -1, -1, -1, -1, 1, 0, -1, -1, -1, 1, 1,
		-1, -1, -1, 1, -1, 0, -1, -1, 1, 0, 0, -1, -1, 1, 1, 0, -1, -1, 1, -1, 1, -1, -1, 1, 0, 1, -1,
		-1, 1, 1, 1, -1, -1, 1, -1, -1, 0, -1, 1, 0, -1, 0, -1, 1, 1, -1, 0, -1, 1, -1, 0, 0, -1, 1,
		0, 0, 0, -1, 1, 1, 0, 0, -1, 1, -1, 1, 0, -1, 1, 0, 1, 0, -1, 1, 1, 1, 0, -1, 1, -1, -1,
		1, -1, 1, 0, -1, 1, -1, 1, 1, -1, 1, -1, 1, -1, 0, 1, -1, 1, 0, 0, 1, -1, 1, 1, 0, 1, -1,
		1, -1, 1, 1, -1, 1, 0, 1, 1, -1, 1, 1, 1, 1, -1, 1, -1, -1, -1, 0, 1, 0, -1, -1, 0, 1, 1,
		-1, -1, 0, 1, -1, 0, -1, 0, 1, 0, 0, -1, 0, 1, 1, 0, -1, 0, 1, -1, 1, -1, 0, 1, 0, 1, -1,
		0, 1, 1, 1, -1, 0, 1, -1, -1, 0, 0, 1, 0, -1, 0, 0, 1, 1, -1, 0, 0, 1, -1, 0, 0, 0, 1,
		0, 0, 0, 0, 1, 1, 0, 0, 0, 1, -1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, -1, -1,
		1, 0, 1, 0, -1, 1, 0, 1, 1, -1, 1, 0, 1, -1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0,
		1, -1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, -1, -1, -1, 1, 1, 0, -1, -1, 1, 1, 1,
		-1, -1, 1, 1, -1, 0, -1, 1, 1, 0, 0, -1, 1, 1, 1, 0, -1, 1, 1, -1, 1, -1, 1, 1, 0, 1, -1,
		1, 1, 1, 1, -1, 1, 1, -1, -1, 0, 1, 1, 0, -1, 0, 1, 1, 1, -1, 0, 1, 1, -1, 0, 0, 1, 1,
		0, 0, 0, 1, 1, 1, 0, 0, 1, 1, -1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, -1, -1,
		1, 1, 1, 0, -1, 1, 1, 1, 1, -1, 1, 1, 1, -1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1,
		1, -1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, 1,
		-1, -1, -1, -1, -1, 0, -1, -1, -1, 0, 0, -1, -1, -1, 1, 0, -1, -1, -1, -1, 1, -1, -1, -1, 0, 1, -1,
		-1, -1, 1, 1, -1, -1, -1, -1, -1, 0, -1, -1, 0, -1, 0, -1, -1, 1, -1, 0, -1, -1, -1, 0, 0, -1, -1,
		0, 0, 0, -1, -1, 1, 0, 0, -1, -1, -1, 1, 0, -1, -1, 0, 1, 0, -1, -1, 1, 1, 0, -1, -1, -1, -1,
		1, -1, -1, 0, -1, 1, -1, -1, 1, -1, 1, -1, -1, -1, 0, 1, -1, -1, 0, 0, 1, -1, -1, 1, 0, 1, -1,
		-1, -1, 1, 1, -1, -1, 0, 1, 1, -1, -1, 1, 1, 1, -1, -1, -1, -1, -1, 0, -1, 0, -1, -1, 0, -1, 1,
		-1, -1, 0, -1, -1, 0, -1, 0, -1, 0, 0, -1, 0, -1, 1, 0, -1, 0, -1, -1, 1, -1, 0, -1, 0, 1, -1,
		0, -1, 1, 1, -1, 0, -1, -1, -1, 0, 0, -1, 0, -1, 0, 0, -1, 1, -1, 0, 0, -1, -1, 0, 0, 0, -1,
		0, 0, 0, 0, -1, 1, 0, 0, 0, -1, -1, 1, 0, 0, -1, 0, 1, 0, 0, -1, 1, 1, 0, 0, -1, -1, -1,
		1, 0, -1, 0, -1, 1, 0, -1, 1, -1, 1, 0, -1, -1, 0, 1, 0, -1, 0, 0, 1, 0, -1, 1, 0, 1, 0,
		-1, -1, 1, 1, 0, -1, 0, 1, 1, 0, -1, 1, 1, 1, 0, -1, -1, -1, -1, 1, -1, 0, -1, -1, 1, -1, 1,
		-1, -1, 1, -1, -1, 0, -1, 1, -1, 0, 0, -1, 1, -1, 1, 0, -1, 1, -1, -1, 1, -1, 1, -1, 0, 1, -1,
		1, -1, 1, 1, -1, 1, -1, -1, -1, 0, 1, -1, 0, -1, 0, 1, -1, 1, -1, 0, 1, -1, -1, 0, 0, 1, -1,
		0, 0, 0, 1, -1, 1, 0, 0, 1, -1, -1, 1, 0, 1, -1, 0, 1, 0, 1, -1, 1, 1, 0, 1, -1, -1, -1,
		1, 1, -1, 0, -1, 1, 1, -1, 1, -1, 1, 1, -1, -1, 0, 1, 1, -1, 0, 0, 1, 1, -1, 1, 0, 1, 1,
		-1, -1, 1, 1, 1, -1, 0, 1, 1, 1, -1, 1, 1, 1, 1, -1, -1, -1, -1, -1, 0, 0, -1, -1, -1, 0, 1,
		-1, -1, -1, 0, -1, 0, -1, -1, 0, 0, 0, -1, -1, 0, 1, 0, -1, -1, 0, -1, 1, -1, -1, 0, 0, 1, -1,
		-1, 0, 1, 1, -1, -1, 0, -1, -1, 0, -1, 0, 0, -1, 0, -1, 0, 1, -1, 0, -1, 0, -1, 0, 0, -1, 0,
		0, 0, 0, -1, 0, 1, 0, 0, -1, 0, -1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 1, 1, 0, -1, 0, -1, -1,
		1, -1, 0, 0, -1, 1, -1, 0, 1, -1, 1, -1, 0, -1, 0, 1, -1, 0, 0, 0, 1, -1, 0, 1, 0, 1, -1,
		0, -1, 1, 1, -1, 0, 0, 1, 1, -1, 0, 1, 1, 1, -1, 0, -1, -1, -1, 0, 0, 0, -1, -1, 0, 0, 1,
		-1, -1, 0, 0, -1, 0, -1, 0, 0, 0, 0, -1, 0, 0, 1, 0, -1, 0, 0, -1, 1, -1, 0, 0, 0, 1, -1,
		0, 0, 1, 1, -1, 0, 0, -1, -1, 0, 0, 0, 0, -1, 0, 0, 0, 1, -1, 0, 0, 0, -1, 0, 0, 0, 0,
	}
)

func BytesToTrits(bytes []byte) Trits {
	size := len(bytes)
	trits := make([]Trit, size*NUMBER_OF_TRITS_IN_A_BYTE)

	for i := 0; i < size; i++ {
		v := int(bytes[i])
		if int8(bytes[i]) < 0 {
			v -= 13
		}

		for j := 0; j < NUMBER_OF_TRITS_IN_A_BYTE; j++ {
			trits[i*NUMBER_OF_TRITS_IN_A_BYTE+j] = BYTES_TO_TRITS[v*NUMBER_OF_TRITS_IN_A_BYTE+j]
		}
	}

	return trits
}

func TritsToString(trits Trits, offset int, size int) string {
	var buffer bytes.Buffer
	for i := 0; i < (size+NUMBER_OF_TRITS_IN_A_TRYTE-1)/NUMBER_OF_TRITS_IN_A_TRYTE; i++ {
		j := int(trits[offset+i*NUMBER_OF_TRITS_IN_A_TRYTE]) + int(trits[offset+i*NUMBER_OF_TRITS_IN_A_TRYTE+1])*NUMBER_OF_TRITS_IN_A_TRYTE + int(trits[offset+i*NUMBER_OF_TRITS_IN_A_TRYTE+2])*NUMBER_OF_TRITS_IN_A_TRYTE*NUMBER_OF_TRITS_IN_A_TRYTE
		if j < 0 {
			j += len(TRYTE_ALPHABET)
		}
		buffer.WriteString(TRYTE_ALPHABET[j])
	}

	return buffer.String()
}

// dct.go - DCT Encoding for Akamai BMP Sensor
package akamai

import (
	"fmt"
	"hash/crc32"
	"math"
	"strings"
)

type DCTEncoder struct{}

func NewDCTEncoder() *DCTEncoder {
	return &DCTEncoder{}
}

// EncodeSensorData encodes sensor values using raw encoding
// Real app uses type 2 (raw) encoding for sensor data
func (e *DCTEncoder) EncodeSensorData(values []float32, threshold float32) (string, int64) {
	if len(values) < 2 {
		return "", 0
	}

	minVal, maxVal := e.getMinMax(values)
	quantized := e.quantize(values, minVal, maxVal)
	encoded := e.runLengthEncode(quantized)
	checksum := e.computeChecksum(encoded)

	// Format: "2;min;max;checksum;encoded" (raw encoding, type=2)
	rawResult := fmt.Sprintf("2;%.2f;%.2f;%d;%s",
		e.round2(minVal), e.round2(maxVal), checksum, encoded)

	return rawResult, checksum + int64(math.Round(float64(minVal)*100)) + int64(math.Round(float64(maxVal)*100))
}

// quantize maps float values to characters A-} (60 levels)
func (e *DCTEncoder) quantize(values []float32, minVal, maxVal float32) string {
	if len(values) == 0 {
		return ""
	}

	var sb strings.Builder
	bucketSize := (maxVal - minVal) / 60.0

	for _, v := range values {
		var c byte
		if bucketSize == 0 || v == maxVal {
			c = '}'
		} else {
			bucket := int(math.Floor(float64((v - minVal) / bucketSize)))
			if bucket > 59 {
				bucket = 59
			}
			c = byte(65 + bucket)
		}

		if c == '\\' {
			c = '.'
		} else if c == '.' {
			c = '\\'
		}

		sb.WriteByte(c)
	}

	return sb.String()
}

// runLengthEncode compresses repeated characters
func (e *DCTEncoder) runLengthEncode(s string) string {
	if len(s) == 0 {
		return ""
	}

	var sb strings.Builder
	i := 0

	for i < len(s) {
		c := s[i]
		count := 1
		j := i + 1

		for j < len(s) && s[j] == c {
			count++
			j++
		}

		if count > 1 {
			sb.WriteString(fmt.Sprintf("%d", count))
		}
		sb.WriteByte(c)
		i = j
	}

	return sb.String()
}

// computeChecksum uses standard CRC32 (IEEE polynomial)
func (e *DCTEncoder) computeChecksum(s string) int64 {
	return int64(crc32.ChecksumIEEE([]byte(s)))
}

// Helper functions

func (e *DCTEncoder) getMinMax(values []float32) (float32, float32) {
	if len(values) == 0 {
		return 0, 0
	}
	min, max := values[0], values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max
}

func (e *DCTEncoder) round2(v float32) float32 {
	return float32(math.Round(float64(v)*100) / 100)
}

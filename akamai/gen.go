package akamai

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"math"
	mrand "math/rand"
	"strings"
	"time"
)

// Device represents Android device fingerprint
type Device struct {
	ID                 string
	Manufacturer       string
	Model              string
	Brand              string
	Product            string
	Device             string
	Board              string
	Hardware           string
	Bootloader         string
	Display            string
	Fingerprint        string
	BuildID            string
	Host               string
	AndroidID          string
	ScreenWidth        int
	ScreenHeight       int
	VersionRelease     string
	VersionSDK         int
	VersionCodename    string
	VersionIncremental string
	Language           string
	Tags               string
	Type               string
	User               string
	PerfBench          []string `json:"perf_bench"`
}

const rsaPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4sA7vA7N/t1SRBS8tugM2X4bB
yl0jaCZLqxPOql+qZ3sP4UFayqJTvXjd7eTjMwg1T70PnmPWyh1hfQr4s12oSVph
TKAjPiWmEBvcpnPPMjr5fGgv0w6+KM9DLTxcktThPZAGoVcoyM/cTO/YsAMIxlmT
zpXBaxddHRwi8S2NvwIDAQAB
-----END PUBLIC KEY-----`

// Generator324 creates v3.2.4-rc3 sensors (Panera format)
type Generator324 struct {
	Device    *Device
	PackageID string
	startTime int64
	aesKey    []byte
	hmacKey   []byte
	rsaPubKey *rsa.PublicKey
}

func NewGenerator324(device *Device, packageID string) *Generator324 {
	block, _ := pem.Decode([]byte(rsaPublicKeyPEM))
	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	rsaPub := pub.(*rsa.PublicKey)
	backdateMs := int64(mrand.Intn(50000) + 10000) // 10-60 seconds ago

	aesKey := make([]byte, 16)
	hmacKey := make([]byte, 32)
	rand.Read(aesKey)
	rand.Read(hmacKey)

	return &Generator324{
		Device:    device,
		PackageID: packageID,
		startTime: time.Now().UnixMilli() - backdateMs,
		aesKey:    aesKey,
		hmacKey:   hmacKey,
		rsaPubKey: rsaPub,
	}
}

func (g *Generator324) Generate() (string, string, error) {
	plaintext := g.buildSensorData()
	encrypted, err := g.encrypt(plaintext)
	if err != nil {
		return "", "", err
	}
	return plaintext, encrypted, nil
}

func (g *Generator324) buildSensorData() string {
	// Sample counts must be power of 2: 4, 8, 16, 32, 64
	// Real app uses 2,8 for quick/fresh sensor (immediate login)
	orientSamples := 8 // Not 4
	motionSamples := 16

	orientationDCT, orientationSum := g.generateOrientationDCT(orientSamples)
	motionDCT, motionSum := g.generateMotionDCT(motionSamples)
	orientationTimeDCT := g.generateTimeDCT(orientSamples)
	motionTimeDCT := g.generateTimeDCT(motionSamples)

	var sb strings.Builder
	sb.WriteString("3.2.4-rc3")
	sb.WriteString("-1,2,-94,-100,")
	sb.WriteString(g.getSystemInfo())
	sb.WriteString("-1,2,-94,-101,do_en,dm_en,t_en")
	sb.WriteString("-1,2,-94,-102,") // Empty - no text timing
	sb.WriteString("-1,2,-94,-108,") // Empty - no text events
	sb.WriteString("-1,2,-94,-117,") // Empty - no touch events
	sb.WriteString("-1,2,-94,-144,")
	sb.WriteString(orientationTimeDCT)
	sb.WriteString("-1,2,-94,-142,")
	sb.WriteString(orientationDCT)
	sb.WriteString("-1,2,-94,-145,")
	sb.WriteString(motionTimeDCT)
	sb.WriteString("-1,2,-94,-143,")
	sb.WriteString(motionDCT)
	sb.WriteString("-1,2,-94,-115,")
	sb.WriteString(g.getVerifyStats(orientationSum, motionSum, orientSamples, motionSamples))
	sb.WriteString("-1,2,-94,-70,")  // Empty (new in 3.2.4)
	sb.WriteString("-1,2,-94,-80,")  // Empty (new in 3.2.4)
	sb.WriteString("-1,2,-94,-120,") // Empty
	sb.WriteString("-1,2,-94,-112,")
	sb.WriteString(g.getPerfStats())
	sb.WriteString("-1,2,-94,-121,") // Empty (new in 3.2.4)
	sb.WriteString("-1,2,-94,-103,")
	sb.WriteString(g.getBackgroundEvents())
	sb.WriteString("-1,2,-94,-150,1,0") // New in 3.2.4

	return sb.String()

}

func (g *Generator324) getSystemInfo() string {
	d := g.Device
	batteryLevel := mrand.Intn(100) + 1

	systemInfo := fmt.Sprintf(
		"-1,uaend,-1,%d,%d,1,%d,1,%s,%s,0,%s,%s,%s,-1,%s,-1,-1,%s,-1,0,1,%s,%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
		d.ScreenHeight, d.ScreenWidth,
		batteryLevel,
		urlEncode(d.Language), urlEncode(d.VersionRelease),
		urlEncode(d.Model), urlEncode(d.Bootloader), urlEncode(d.Hardware),
		g.PackageID, d.AndroidID,
		urlEncode(d.VersionCodename), urlEncode(d.VersionIncremental),
		d.VersionSDK,
		urlEncode(d.Manufacturer), urlEncode(d.Product),
		urlEncode(d.Tags), urlEncode(d.Type), urlEncode(d.User),
		urlEncode(d.Display), urlEncode(d.Board), urlEncode(d.Brand),
		urlEncode(d.Device), d.Fingerprint, urlEncode(d.Host),
		urlEncode(d.BuildID),
	)

	abChecksum := ab(systemInfo)
	negatedRand := int32(mrand.Uint32())
	return fmt.Sprintf("%s,%d,%d,%d", systemInfo, abChecksum, negatedRand, g.startTime/2)
}

func (g *Generator324) generateOrientationDCT(samples int) (string, int64) {
	var parts []string
	var totalSum int64

	// Orientation: azimuth (~230-270), pitch (~1.5-2), roll (~1.5-2)
	bases := []float32{
		float32(230 + mrand.Float64()*40),  // azimuth
		float32(1.5 + mrand.Float64()*0.5), // pitch
		float32(1.5 + mrand.Float64()*0.5), // roll
	}

	for _, base := range bases {
		values := make([]float32, samples)
		for i := 0; i < samples; i++ {
			values[i] = base + float32(mrand.Float64()*0.5-0.25)
		}
		encoded, sum := encodeDCT(values)
		parts = append(parts, encoded)
		totalSum += sum
	}

	return strings.Join(parts, ":"), totalSum
}

func (g *Generator324) generateMotionDCT(samples int) (string, int64) {
	var parts []string
	var totalSum int64

	// Motion: 9 axes
	// [0-2] accelerometer x,y,z
	// [3-5] gyroscope x,y,z
	// [6-8] linear acceleration x,y,z
	bases := []float32{
		float32(mrand.Float64()*0.2 - 0.1),    // accel x
		float32(mrand.Float64()*0.2 - 0.1),    // accel y
		float32(-5.5 + mrand.Float64()*0.5),   // accel z (gravity component)
		float32(mrand.Float64()*0.4 - 0.2),    // gyro x
		float32(mrand.Float64()*0.4 - 0.2),    // gyro y
		float32(-9.81 + mrand.Float64()*0.02), // gyro z
		float32(mrand.Float64()*0.2 - 0.1),    // linear x
		float32(mrand.Float64()*0.2 - 0.1),    // linear y
		float32(mrand.Float64()*0.2 - 0.1),    // linear z
	}

	for _, base := range bases {
		values := make([]float32, samples)
		for i := 0; i < samples; i++ {
			values[i] = base + float32(mrand.Float64()*0.1-0.05)
		}
		encoded, sum := encodeDCT(values)
		parts = append(parts, encoded)
		totalSum += sum
	}

	return strings.Join(parts, ":"), totalSum
}

func (g *Generator324) generateTimeDCT(samples int) string {
	values := make([]float32, samples)
	for i := 0; i < samples; i++ {
		// Mostly 100-250ms intervals, occasional longer gaps
		if mrand.Float64() < 0.15 {
			values[i] = float32(500 + mrand.Intn(800))
		} else {
			values[i] = float32(100 + mrand.Intn(150))
		}
	}
	encoded, _ := encodeDCT(values)
	return encoded
}

// getVerifyStats builds -115 section
// Real format: 0,0,orientSum,motionSum,totalSum,elapsedMs,0,0,orientSamples,motionSamples,2000,buildTime,1,feistel,startTimestamp
func (g *Generator324) getVerifyStats(orientationSum, motionSum int64, orientSamples, motionSamples int) string {
	totalSum := orientationSum + motionSum
	elapsedMs := mrand.Intn(2000) + 1500   // 1500-3500ms (real: ~2164)
	buildTime := mrand.Intn(20000) + 25000 // 25000-45000 microseconds (real: ~34000)

	// Feistel computation from JADX:
	// g.c((int)elapsed, (totalSum << 32) | ((textCount + touchCount + orientSamples + motionSamples) & 0xFFFFFFFF))
	combined := (totalSum << 32) | (int64(orientSamples+motionSamples) & 0xFFFFFFFF)
	feistel := computeFeistel(elapsedMs, combined)

	return fmt.Sprintf("0,0,%d,%d,%d,%d,0,0,%d,%d,2000,%d,1,%d,%d",
		orientationSum, motionSum, totalSum, elapsedMs,
		orientSamples, motionSamples, buildTime, feistel, g.startTime)
}

func (g *Generator324) getPerfStats() string {
	// From real capture: 17,1297,59,1666,126700,1275,33400,333,64354

	if len(g.Device.PerfBench) > 0 {
		return g.Device.PerfBench[mrand.Intn(len(g.Device.PerfBench))]
	}

	return fmt.Sprintf("%d,%d,%d,%d,%d,%d,%d,%d,%d",
		mrand.Intn(20)+10,       // 10-30
		mrand.Intn(1000)+400,    // 400-1400
		mrand.Intn(80)+40,       // 40-120
		mrand.Intn(1200)+600,    // 600-1800
		mrand.Intn(80000)+60000, // 60000-140000
		mrand.Intn(1000)+400,    // 400-1400
		mrand.Intn(20000)+20000, // 20000-40000
		mrand.Intn(300)+150,     // 150-450
		mrand.Intn(40000)+40000) // 40000-80000
}

func (g *Generator324) getBackgroundEvents() string {
	ts := g.startTime
	t1 := ts + mrand.Int63n(200) + 50
	t2 := t1 + mrand.Int63n(2000) + 1000

	// Sometimes only 2 events
	if mrand.Float32() < 0.3 {
		return fmt.Sprintf("3,%d;2,%d;", t1, t2)
	}

	t3 := t2 + mrand.Int63n(100) + 20
	return fmt.Sprintf("3,%d;2,%d;3,%d;", t1, t2, t3)
}

// encrypt with correct format: ends with $$
func (g *Generator324) encrypt(plaintext string) (string, error) {
	block, _ := aes.NewCipher(g.aesKey)
	iv := make([]byte, 16)
	rand.Read(iv)

	padded := pkcs7Pad([]byte(plaintext), 16)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	combined := append(iv, ciphertext...)
	mac := hmac.New(sha256.New, g.hmacKey)
	mac.Write(combined)
	combined = append(combined, mac.Sum(nil)...)

	encAES, _ := rsa.EncryptPKCS1v15(rand.Reader, g.rsaPubKey, g.aesKey)
	encHMAC, _ := rsa.EncryptPKCS1v15(rand.Reader, g.rsaPubKey, g.hmacKey)

	// Real app format ends with $$ (from HTTP capture)
	aesTime := (mrand.Intn(3) + 1) * 1000 // 1000, 2000, or 3000

	return fmt.Sprintf("2,a,%s,%s$%s$%d,0,0$$",
		base64.StdEncoding.EncodeToString(encAES),
		base64.StdEncoding.EncodeToString(encHMAC),
		base64.StdEncoding.EncodeToString(combined),
		aesTime), nil
}

func computeFeistel(elapsed int, combined int64) int64 {
	left := int32(combined)
	right := int32(combined >> 32)
	for i := 0; i < 16; i++ {
		shift := i % 32
		rotated := (elapsed << shift) | (elapsed >> (32 - shift))
		if shift == 0 {
			rotated = elapsed // No rotation needed
		}
		newLeft := right ^ (int32(rotated) ^ left)
		right = left
		left = newLeft
	}
	// Return as unsigned
	return int64(uint64(uint32(right))<<32 | uint64(uint32(left)))
}

func ab(s string) int {
	sum := 0
	for _, c := range s {
		if c < 128 {
			sum += int(c)
		}
	}
	return sum
}

func encodeDCT(values []float32) (string, int64) {
	if len(values) == 0 {
		return "", 0
	}

	minVal, maxVal := values[0], values[0]
	for _, v := range values[1:] {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
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

	quantized := sb.String()
	encoded := runLengthEncode(quantized)
	checksum := int64(crc32.ChecksumIEEE([]byte(encoded)))

	minRound := float32(math.Round(float64(minVal)*100) / 100)
	maxRound := float32(math.Round(float64(maxVal)*100) / 100)

	return fmt.Sprintf("2;%.2f;%.2f;%d;%s", minRound, maxRound, checksum, encoded),
		checksum + int64(math.Round(float64(minVal)*100)) + int64(math.Round(float64(maxVal)*100))
}

func runLengthEncode(s string) string {
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

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padBytes := make([]byte, padding)
	for i := range padBytes {
		padBytes[i] = byte(padding)
	}
	return append(data, padBytes...)
}

func urlEncode(s string) string {
	return strings.ReplaceAll(s, " ", "%20")
}

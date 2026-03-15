package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	bmp324 "bmp/v324"
)

type AkamaiRequest struct {
	App     string `json:"app"`
	Version string `json:"version"`
}

type AkamaiResponse struct {
	SensorData     string `json:"sensor"`
	AndroidVersion string `json:"androidVersion"`
	Model          string `json:"model"`
	Brand          string `json:"brand"`
	ScreenSize     string `json:"screenSize"`
	BuildID        string `json:"buildID"`
}

var devices []bmp324.Device

func loadDevices(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var rawDevices []map[string]interface{}
	if err := json.Unmarshal(data, &rawDevices); err != nil {
		return err
	}

	for _, raw := range rawDevices {
		device := bmp324.Device{
			ID:                 getString(raw, "id"),
			Manufacturer:       getString(raw, "manufacturer"),
			Model:              getString(raw, "model"),
			Brand:              getString(raw, "brand"),
			Product:            getString(raw, "product"),
			Device:             getString(raw, "device"),
			Board:              getString(raw, "board"),
			Hardware:           getString(raw, "hardware"),
			Bootloader:         getString(raw, "bootloader"),
			Display:            getString(raw, "display"),
			Fingerprint:        getString(raw, "fingerprint"),
			BuildID:            getString(raw, "build_id"),
			Host:               getString(raw, "host"),
			AndroidID:          generateAndroidID(),
			ScreenWidth:        getInt(raw, "screen_width", 1080),
			ScreenHeight:       getInt(raw, "screen_height", 1920),
			VersionRelease:     getString(raw, "version_release"),
			VersionSDK:         getInt(raw, "version_sdk", 29),
			VersionCodename:    getStringDefault(raw, "version_codename", "REL"),
			VersionIncremental: getString(raw, "version_incremental"),
			Language:           getStringDefault(raw, "language", "en"),
			Tags:               getStringDefault(raw, "tags", "release-keys"),
			Type:               getStringDefault(raw, "type", "user"),
			User:               getString(raw, "user"),
			PerfBench:          getStringArray(raw, "perf_bench"),
		}
		devices = append(devices, device)
	}

	return nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getStringDefault(m map[string]interface{}, key, def string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}

func getInt(m map[string]interface{}, key string, def int) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return def
}

func getFloat(m map[string]interface{}, key string, def float64) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return def
}

func getStringArray(m map[string]interface{}, key string) []string {
	if v, ok := m[key].([]interface{}); ok {
		result := make([]string, len(v))
		for i, item := range v {
			if s, ok := item.(string); ok {
				result[i] = s
			}
		}
		return result
	}
	return nil
}

func generateAndroidID() string {
	const chars = "0123456789abcdef"
	b := make([]byte, 16)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func handleBmpRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AkamaiRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	if req.App == "" {
		http.Error(w, "app field required", http.StatusBadRequest)
		return
	}

	// Only v3.2.4 supported currently
	if req.Version != "" && req.Version != "3.2.4" {
		http.Error(w, "BMP version not supported (only 3.2.4)", http.StatusBadRequest)
		return
	}

	// Pick random device
	device := devices[rand.Intn(len(devices))]
	device.AndroidID = generateAndroidID()

	generator := bmp324.NewGenerator324(&device, req.App)
	_, sensor, err := generator.Generate()
	if err != nil {
		http.Error(w, "Error generating sensor data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := AkamaiResponse{
		SensorData:     sensor,
		AndroidVersion: device.VersionRelease,
		Model:          device.Model,
		Brand:          device.Brand,
		ScreenSize:     fmt.Sprintf("%dx%d", device.ScreenWidth, device.ScreenHeight),
		BuildID:        device.BuildID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	rand.Seed(time.Now().UnixNano())

	var (
		host       string
		port       int
		devicePath string
	)

	flag.StringVar(&host, "host", "localhost", "Host to run server on")
	flag.IntVar(&port, "port", 1337, "Port to run server on")
	flag.StringVar(&devicePath, "devices", "devices.json", "Path to devices.json")
	help := flag.Bool("h", false, "Display help")
	flag.Parse()

	if *help {
		fmt.Println("Akamai BMP Sensor Generator")
		flag.PrintDefaults()
		return
	}

	if err := loadDevices(devicePath); err != nil {
		log.Fatalf("Failed to load devices: %v", err)
	}
	log.Printf("Loaded %d devices", len(devices))

	addr := fmt.Sprintf("%s:%d", host, port)
	http.HandleFunc("/akamai/bmp", handleBmpRequest)

	log.Printf("Starting server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

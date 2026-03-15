# Akamai BMP Generator

Go implementation of Akamai Bot Manager Premier sensor generation for Android.

## Disclaimer

This tool is for educational and research purposes only. Use responsibly and in accordance with applicable laws and terms of service. The author is not responsible for any misuse.

## Usage

```bash
go run main.go -devices devices.json -port 1337
```

```bash
curl -X POST http://localhost:1337/akamai/bmp \
  -H "Content-Type: application/json" \
  -d '{"app": "com.example.app"}'
```

![API Response](/docs/api.png)

## Structure

```
├── akamai/
│   ├── gen.go      # sensor generator
│   └── dct.go      # DCT encoding
├── devices.json    # device fingerprints
└── main.go         # http server
```

## Notes

- Requires device fingerprints with performance benchmark data (section -112)
- Each request returns a random device from the pool
- Build your own User-Agent from the response fields

## License

MIT
# JSNiper

A fast JavaScript file hunter and secret scanner written in Rust. This tool crawls websites, extracts JavaScript files, and scans them for secrets and sensitive information using regex patterns.

This was fully "vibe coded" using claude-code. And all the patterns are taken from [Reghex](https://github.com/l4yton/RegHex)

## Features

- **High Performance**: Async/await with configurable concurrency
- **Content Deduplication**: Uses SHA-256 hashing to avoid processing duplicate files
- **Comprehensive Scanning**: Scans for API keys, tokens, credentials, and other secrets
- **Detailed Reporting**: CSV output with full metadata
- **Extensible Patterns**: JSON-based pattern configuration
- **Progress Tracking**: Real-time progress updates

## Installation

```bash
cargo build --release
```

## Usage

```bash
./target/release/jsniper --urls urls.txt --output ./results --workers 100 --patterns patterns.json
```

### Arguments

- `--urls`: Text file containing URLs (one per line)
- `--output`: Output directory for results
- `--workers`: Number of concurrent workers (default: 50)
- `--patterns`: JSON file containing regex patterns

## Input Format

### URLs File
```
https://example.com
https://test.com/page
https://another-site.org
```

### Patterns File
The tool includes a comprehensive `patterns.json` file with common secret patterns. You can customize it to add your own patterns:

```json
{
  "patterns": {
    "custom_api_key": {
      "regex": "CUSTOM_[0-9A-Z]{32}",
      "description": "Custom API Key"
    }
  }
}
```

## Output

### Directory Structure
```
results/
├── js_files/
│   ├── a1b2c3d4e5f6...js    # Content-addressed JS files
│   └── f6e5d4c3b2a1...js
├── scan_results.csv          # Main results
└── run_metadata.json        # Run statistics
```

### CSV Output Format
- `url`: Original page URL
- `js_path`: Full URL to the JS file
- `filename`: Extracted filename
- `hash`: SHA-256 hash of content
- `status`: HTTP status code
- `secrets_found`: Boolean indicating if secrets were found
- `regex_matches`: Comma-separated list of matching pattern names
- `file_size`: Size in bytes
- `fetch_time`: ISO 8601 timestamp

## Security Note

This tool is designed for security research and authorized testing only. Ensure you have permission to scan target websites and handle any discovered secrets responsibly.

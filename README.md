# netser-signatures

A Python library for network service signature detection. This tool helps identify network services by analyzing port numbers, protocols, and data patterns.

## Features

- **Port-based Detection**: Identify services by their default port numbers
- **Pattern-based Detection**: Analyze service banners and protocol signatures
- **Extensible Database**: Built-in database of common services with ability to add custom signatures
- **Command-line Interface**: Easy-to-use CLI tool for quick service detection
- **Python API**: Comprehensive API for programmatic service detection

## Installation

```bash
# Clone the repository
git clone https://github.com/dannyjo4/netser-signatures.git
cd netser-signatures

# Install in development mode
pip install -e .

# Or install from requirements
pip install -r requirements.txt
```

## Quick Start

### Command Line Usage

```bash
# Detect service by port
netser-detect --port 80

# Detect service by port and protocol
netser-detect --port 53 --protocol udp

# List all known signatures
netser-detect --list

# Show details for a specific signature
netser-detect --info HTTP

# Output in JSON format
netser-detect --port 80 --json
```

### Python API Usage

```python
from netser_signatures import SignatureDetector, Signature, SignatureDatabase

# Basic detection by port
detector = SignatureDetector()
result = detector.detect(80, "tcp")
print(f"Service: {result.get_best_match().name}")

# Detection with data analysis
http_data = b"GET / HTTP/1.1\r\n"
result = detector.detect(80, "tcp", http_data)
print(f"Confidence: {result.confidence:.0%}")

# Detect multiple services
services = [
    {"port": 80, "protocol": "tcp"},
    {"port": 443, "protocol": "tcp"},
]
results = detector.detect_multiple(services)

# Custom signature database
db = SignatureDatabase()
custom_sig = Signature("MyService", 9999, "tcp", 
                      patterns=["MYPROTO"], 
                      description="Custom service")
db.add_signature(custom_sig)
detector = SignatureDetector(database=db)
```

## Built-in Signatures

The library includes signatures for common network services:

- **HTTP** (80/tcp) - Hypertext Transfer Protocol
- **HTTPS** (443/tcp) - Secure HTTP over TLS/SSL
- **SSH** (22/tcp) - Secure Shell Protocol
- **FTP** (21/tcp) - File Transfer Protocol
- **SMTP** (25/tcp) - Simple Mail Transfer Protocol
- **DNS** (53/udp) - Domain Name System
- **MySQL** (3306/tcp) - MySQL Database
- **PostgreSQL** (5432/tcp) - PostgreSQL Database
- **Redis** (6379/tcp) - Redis In-Memory Database
- **MongoDB** (27017/tcp) - MongoDB NoSQL Database

## Testing

Run the test suite:

```bash
# Install test dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=netser_signatures --cov-report=term-missing
```

## Architecture

### Core Components

1. **Signature**: Represents a network service signature with port, protocol, and pattern information
2. **SignatureDatabase**: Manages a collection of signatures with search and persistence capabilities
3. **SignatureDetector**: Performs service detection using port and pattern matching
4. **DetectionResult**: Contains detection results with confidence scores

### Detection Methods

- **Port-based**: Matches services by their default ports (moderate confidence)
- **Pattern-based**: Analyzes service banners and protocol signatures (high confidence)
- **Combined**: Uses both port and pattern information (highest confidence)

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is open source and available under the MIT License.

"""
Example usage of netser-signatures library.

This example demonstrates various ways to use the library for
network service signature detection.
"""

from netser_signatures import SignatureDetector, Signature, SignatureDatabase


def example_basic_detection():
    """Basic port-based service detection."""
    print("=== Basic Port Detection ===")
    detector = SignatureDetector()
    
    # Detect common services
    common_ports = [
        (80, "tcp"),
        (443, "tcp"),
        (22, "tcp"),
        (21, "tcp"),
        (25, "tcp"),
        (53, "udp"),
    ]
    
    for port, protocol in common_ports:
        result = detector.detect(port, protocol)
        if result.matches:
            match = result.get_best_match()
            print(f"Port {port}/{protocol.upper()}: {match.name} - {match.description}")
    print()


def example_pattern_detection():
    """Pattern-based service detection."""
    print("=== Pattern-Based Detection ===")
    detector = SignatureDetector()
    
    # Simulate service banners
    test_data = [
        (b"GET / HTTP/1.1\r\n", "HTTP request"),
        (b"HTTP/1.1 200 OK\r\n", "HTTP response"),
        (b"SSH-2.0-OpenSSH_8.2p1\r\n", "SSH banner"),
        (b"220 FTP Server ready\r\n", "FTP banner"),
        (b"+PONG\r\n", "Redis response"),
    ]
    
    for data, description in test_data:
        result = detector.detect_by_data(data)
        if result.matches:
            match = result.get_best_match()
            print(f"{description}: Detected as {match.name} (confidence: {result.confidence:.0%})")
    print()


def example_combined_detection():
    """Combined port and pattern detection."""
    print("=== Combined Detection (Port + Pattern) ===")
    detector = SignatureDetector()
    
    # Test with both port and data
    test_cases = [
        (80, "tcp", b"GET / HTTP/1.1\r\n", "HTTP on standard port"),
        (8080, "tcp", b"HTTP/1.1 200 OK\r\n", "HTTP on alternate port"),
        (22, "tcp", b"SSH-2.0-OpenSSH\r\n", "SSH on standard port"),
    ]
    
    for port, protocol, data, description in test_cases:
        result = detector.detect(port, protocol, data)
        if result.matches:
            match = result.get_best_match()
            print(f"{description}: {match.name} (confidence: {result.confidence:.0%})")
    print()


def example_custom_signatures():
    """Adding and using custom signatures."""
    print("=== Custom Signatures ===")
    
    # Create a custom database
    db = SignatureDatabase()
    
    # Add custom signatures
    custom_services = [
        Signature("Jenkins", 8080, "tcp", 
                 patterns=["Jenkins", "X-Jenkins"],
                 description="Jenkins CI/CD Server"),
        Signature("Elasticsearch", 9200, "tcp",
                 patterns=["elasticsearch"],
                 description="Elasticsearch Search Engine"),
        Signature("Prometheus", 9090, "tcp",
                 description="Prometheus Monitoring"),
    ]
    
    for sig in custom_services:
        db.add_signature(sig)
    
    detector = SignatureDetector(database=db)
    
    # Test custom signatures
    print("Added custom signatures:")
    for sig in custom_services:
        result = detector.detect(sig.port, sig.protocol)
        if result.matches:
            match = result.get_best_match()
            print(f"  {match.name} ({match.port}/{match.protocol.upper()}): {match.description}")
    print()


def example_batch_detection():
    """Batch detection of multiple services."""
    print("=== Batch Service Detection ===")
    detector = SignatureDetector()
    
    # Simulate a network scan result
    discovered_services = [
        {"port": 80, "protocol": "tcp"},
        {"port": 443, "protocol": "tcp"},
        {"port": 22, "protocol": "tcp"},
        {"port": 3306, "protocol": "tcp"},
        {"port": 6379, "protocol": "tcp", "data": b"+PONG\r\n"},
        {"port": 27017, "protocol": "tcp"},
    ]
    
    results = detector.detect_multiple(discovered_services)
    
    print("Detected services:")
    for result in results:
        if result.matches:
            match = result.get_best_match()
            print(f"  Port {result.port}/{result.protocol.upper()}: {match.name}")
    print()


def example_signature_persistence():
    """Save and load signature databases."""
    print("=== Signature Database Persistence ===")
    
    # Create a custom database
    db = SignatureDatabase()
    db.add_signature(Signature("CustomApp", 9999, "tcp", 
                               description="My Custom Application"))
    
    # Save to file
    db.save_to_file("/tmp/signatures.json")
    print("Signatures saved to /tmp/signatures.json")
    
    # Load from file
    db2 = SignatureDatabase()
    db2.signatures = []  # Clear defaults
    db2.load_from_file("/tmp/signatures.json")
    print(f"Loaded {len(db2)} signatures from file")
    
    # Verify
    custom = db2.find_by_name("CustomApp")
    if custom:
        print(f"Found custom signature: {custom.name} on port {custom.port}")
    print()


def main():
    """Run all examples."""
    print("netser-signatures Library Examples\n")
    print("=" * 60)
    print()
    
    example_basic_detection()
    example_pattern_detection()
    example_combined_detection()
    example_custom_signatures()
    example_batch_detection()
    example_signature_persistence()
    
    print("=" * 60)
    print("All examples completed successfully!")


if __name__ == "__main__":
    main()

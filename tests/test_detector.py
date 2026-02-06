"""Tests for signature detector."""

import pytest
from netser_signatures.detector import SignatureDetector, DetectionResult
from netser_signatures.signatures import Signature, SignatureDatabase


class TestDetectionResult:
    """Test cases for DetectionResult class."""
    
    def test_result_creation(self):
        """Test creating a detection result."""
        result = DetectionResult(80, "tcp")
        
        assert result.port == 80
        assert result.protocol == "tcp"
        assert result.matches == []
        assert result.confidence == 0.0
    
    def test_add_match(self):
        """Test adding matches to result."""
        result = DetectionResult(80, "tcp")
        sig = Signature("HTTP", 80, "tcp")
        
        result.add_match(sig, confidence=0.9)
        
        assert len(result.matches) == 1
        assert result.confidence == 0.9
    
    def test_get_best_match(self):
        """Test getting best match."""
        result = DetectionResult(80, "tcp")
        
        # No matches
        assert result.get_best_match() is None
        
        # Add a match
        sig = Signature("HTTP", 80, "tcp")
        result.add_match(sig)
        
        assert result.get_best_match() == sig
    
    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = DetectionResult(80, "tcp")
        sig = Signature("HTTP", 80, "tcp")
        result.add_match(sig, confidence=0.9)
        
        data = result.to_dict()
        
        assert data["port"] == 80
        assert data["protocol"] == "tcp"
        assert data["matches"] == ["HTTP"]
        assert data["best_match"] == "HTTP"
        assert data["confidence"] == 0.9


class TestSignatureDetector:
    """Test cases for SignatureDetector class."""
    
    def test_detector_creation(self):
        """Test creating a detector."""
        detector = SignatureDetector()
        
        assert detector.database is not None
        assert len(detector.database) > 0
    
    def test_detector_with_custom_database(self):
        """Test creating detector with custom database."""
        db = SignatureDatabase()
        detector = SignatureDetector(database=db)
        
        assert detector.database == db
    
    def test_detect_by_port_tcp(self):
        """Test detecting service by TCP port."""
        detector = SignatureDetector()
        
        result = detector.detect_by_port(80, "tcp")
        
        assert result.port == 80
        assert result.protocol == "tcp"
        assert len(result.matches) > 0
        assert result.get_best_match().name == "HTTP"
    
    def test_detect_by_port_udp(self):
        """Test detecting service by UDP port."""
        detector = SignatureDetector()
        
        result = detector.detect_by_port(53, "udp")
        
        assert result.port == 53
        assert result.protocol == "udp"
        assert len(result.matches) > 0
        assert result.get_best_match().name == "DNS"
    
    def test_detect_by_port_unknown(self):
        """Test detecting unknown port."""
        detector = SignatureDetector()
        
        result = detector.detect_by_port(99999, "tcp")
        
        assert result.port == 99999
        assert len(result.matches) == 0
    
    def test_detect_by_data(self):
        """Test detecting service by data pattern."""
        detector = SignatureDetector()
        
        # HTTP data
        http_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n"
        result = detector.detect_by_data(http_data)
        
        assert len(result.matches) > 0
        assert any(sig.name == "HTTP" for sig in result.matches)
        assert result.confidence >= 0.9
    
    def test_detect_by_data_with_port(self):
        """Test detecting service by data and port."""
        detector = SignatureDetector()
        
        # HTTP data on port 80
        http_data = b"HTTP/1.1 200 OK\r\n"
        result = detector.detect_by_data(http_data, port=80, protocol="tcp")
        
        assert len(result.matches) > 0
        assert result.get_best_match().name == "HTTP"
        assert result.confidence == 1.0  # Perfect match
    
    def test_detect_by_data_ssh(self):
        """Test detecting SSH by data pattern."""
        detector = SignatureDetector()
        
        ssh_data = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
        result = detector.detect_by_data(ssh_data, port=22)
        
        assert len(result.matches) > 0
        assert result.get_best_match().name == "SSH"
    
    def test_detect_combined(self):
        """Test comprehensive detection."""
        detector = SignatureDetector()
        
        # With data
        http_data = b"GET / HTTP/1.1\r\n"
        result = detector.detect(80, "tcp", http_data)
        
        assert result.port == 80
        assert len(result.matches) > 0
        assert result.get_best_match().name == "HTTP"
        
        # Without data
        result = detector.detect(443, "tcp")
        
        assert result.port == 443
        assert len(result.matches) > 0
        assert result.get_best_match().name == "HTTPS"
    
    def test_detect_multiple(self):
        """Test detecting multiple services."""
        detector = SignatureDetector()
        
        services = [
            {"port": 80, "protocol": "tcp"},
            {"port": 443, "protocol": "tcp"},
            {"port": 22, "protocol": "tcp", "data": b"SSH-2.0"},
        ]
        
        results = detector.detect_multiple(services)
        
        assert len(results) == 3
        assert results[0].get_best_match().name == "HTTP"
        assert results[1].get_best_match().name == "HTTPS"
        assert results[2].get_best_match().name == "SSH"
    
    def test_detect_by_data_fallback_to_port(self):
        """Test fallback to port detection when no pattern matches."""
        detector = SignatureDetector()
        
        # Unknown data but known port
        unknown_data = b"UNKNOWN PROTOCOL DATA"
        result = detector.detect_by_data(unknown_data, port=80)
        
        assert len(result.matches) > 0
        assert result.get_best_match().name == "HTTP"
        assert result.confidence == 0.5  # Low confidence (port only)

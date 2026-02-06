"""Tests for signature definitions and database."""

import pytest
import tempfile
import json
import os
from netser_signatures.signatures import Signature, SignatureDatabase


class TestSignature:
    """Test cases for Signature class."""
    
    def test_signature_creation(self):
        """Test creating a basic signature."""
        sig = Signature("HTTP", 80, "tcp", patterns=["HTTP/1.1"], 
                       description="HTTP Protocol")
        
        assert sig.name == "HTTP"
        assert sig.port == 80
        assert sig.protocol == "tcp"
        assert sig.patterns == ["HTTP/1.1"]
        assert sig.description == "HTTP Protocol"
    
    def test_signature_default_values(self):
        """Test signature with default values."""
        sig = Signature("TEST", 8080)
        
        assert sig.protocol == "tcp"
        assert sig.patterns == []
        assert sig.description == ""
    
    def test_matches_port(self):
        """Test port matching."""
        sig = Signature("HTTP", 80, "tcp")
        
        assert sig.matches_port(80, "tcp") is True
        assert sig.matches_port(80, "TCP") is True  # Case insensitive
        assert sig.matches_port(443, "tcp") is False
        assert sig.matches_port(80, "udp") is False
    
    def test_matches_pattern(self):
        """Test pattern matching."""
        sig = Signature("HTTP", 80, patterns=["HTTP/1.1", "GET "])
        
        assert sig.matches_pattern(b"GET / HTTP/1.1\r\n") is True
        assert sig.matches_pattern(b"HTTP/1.1 200 OK\r\n") is True
        assert sig.matches_pattern(b"SSH-2.0-OpenSSH") is False
    
    def test_matches_pattern_empty(self):
        """Test pattern matching with no patterns."""
        sig = Signature("HTTP", 80, patterns=[])
        
        assert sig.matches_pattern(b"GET / HTTP/1.1\r\n") is False
    
    def test_to_dict(self):
        """Test converting signature to dictionary."""
        sig = Signature("HTTP", 80, "tcp", patterns=["HTTP/1.1"], 
                       description="HTTP Protocol")
        data = sig.to_dict()
        
        assert data["name"] == "HTTP"
        assert data["port"] == 80
        assert data["protocol"] == "tcp"
        assert data["patterns"] == ["HTTP/1.1"]
        assert data["description"] == "HTTP Protocol"
    
    def test_from_dict(self):
        """Test creating signature from dictionary."""
        data = {
            "name": "HTTP",
            "port": 80,
            "protocol": "tcp",
            "patterns": ["HTTP/1.1"],
            "description": "HTTP Protocol"
        }
        sig = Signature.from_dict(data)
        
        assert sig.name == "HTTP"
        assert sig.port == 80
        assert sig.protocol == "tcp"
        assert sig.patterns == ["HTTP/1.1"]
        assert sig.description == "HTTP Protocol"
    
    def test_repr(self):
        """Test string representation."""
        sig = Signature("HTTP", 80, "tcp")
        assert "HTTP" in repr(sig)
        assert "80" in repr(sig)


class TestSignatureDatabase:
    """Test cases for SignatureDatabase class."""
    
    def test_database_creation(self):
        """Test creating a database with default signatures."""
        db = SignatureDatabase()
        
        assert len(db) > 0
        assert db.find_by_name("HTTP") is not None
        assert db.find_by_name("SSH") is not None
    
    def test_add_signature(self):
        """Test adding a custom signature."""
        db = SignatureDatabase()
        initial_count = len(db)
        
        custom = Signature("CUSTOM", 9999, "tcp")
        db.add_signature(custom)
        
        assert len(db) == initial_count + 1
        assert db.find_by_name("CUSTOM") is not None
    
    def test_remove_signature(self):
        """Test removing a signature."""
        db = SignatureDatabase()
        
        # Add a custom signature
        custom = Signature("CUSTOM", 9999, "tcp")
        db.add_signature(custom)
        
        # Remove it
        assert db.remove_signature("CUSTOM") is True
        assert db.find_by_name("CUSTOM") is None
        
        # Try to remove non-existent signature
        assert db.remove_signature("NONEXISTENT") is False
    
    def test_find_by_port(self):
        """Test finding signatures by port."""
        db = SignatureDatabase()
        
        results = db.find_by_port(80, "tcp")
        assert len(results) > 0
        assert any(sig.name == "HTTP" for sig in results)
        
        results = db.find_by_port(53, "udp")
        assert len(results) > 0
        assert any(sig.name == "DNS" for sig in results)
    
    def test_find_by_name(self):
        """Test finding signature by name."""
        db = SignatureDatabase()
        
        sig = db.find_by_name("HTTP")
        assert sig is not None
        assert sig.port == 80
        
        sig = db.find_by_name("NONEXISTENT")
        assert sig is None
    
    def test_find_by_pattern(self):
        """Test finding signatures by pattern."""
        db = SignatureDatabase()
        
        results = db.find_by_pattern(b"HTTP/1.1 200 OK")
        assert len(results) > 0
        assert any(sig.name == "HTTP" for sig in results)
        
        results = db.find_by_pattern(b"SSH-2.0-OpenSSH")
        assert len(results) > 0
        assert any(sig.name == "SSH" for sig in results)
    
    def test_get_all_signatures(self):
        """Test getting all signatures."""
        db = SignatureDatabase()
        
        all_sigs = db.get_all_signatures()
        assert len(all_sigs) == len(db)
        assert isinstance(all_sigs, list)
    
    def test_save_and_load(self):
        """Test saving to and loading from file."""
        db = SignatureDatabase()
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            # Save to file
            db.save_to_file(temp_file)
            
            # Create new database and load
            db2 = SignatureDatabase()
            db2.signatures = []  # Clear default signatures
            db2.load_from_file(temp_file)
            
            # Verify
            assert len(db2) == len(db)
            assert db2.find_by_name("HTTP") is not None
        finally:
            # Clean up
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_repr(self):
        """Test string representation."""
        db = SignatureDatabase()
        assert "SignatureDatabase" in repr(db)
        assert str(len(db)) in repr(db)

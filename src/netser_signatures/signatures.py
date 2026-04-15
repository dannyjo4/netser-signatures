"""
Signature definitions and database for network services.
"""

from typing import List, Dict, Optional, Any
import json


class Signature:
    """Represents a network service signature."""
    
    def __init__(self, name: str, port: int, protocol: str = "tcp", 
                 patterns: Optional[List[str]] = None, description: str = ""):
        """
        Initialize a service signature.
        
        Args:
            name: Service name (e.g., "HTTP", "SSH")
            port: Default port number
            protocol: Protocol type ("tcp" or "udp")
            patterns: List of byte patterns or regex patterns to match
            description: Human-readable description
        """
        self.name = name
        self.port = port
        self.protocol = protocol.lower()
        self.patterns = patterns or []
        self.description = description
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert signature to dictionary."""
        return {
            "name": self.name,
            "port": self.port,
            "protocol": self.protocol,
            "patterns": self.patterns,
            "description": self.description
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Signature":
        """Create signature from dictionary."""
        return cls(
            name=data["name"],
            port=data["port"],
            protocol=data.get("protocol", "tcp"),
            patterns=data.get("patterns", []),
            description=data.get("description", "")
        )
    
    def matches_port(self, port: int, protocol: str = "tcp") -> bool:
        """Check if port and protocol match this signature."""
        return self.port == port and self.protocol.lower() == protocol.lower()
    
    def matches_pattern(self, data: bytes) -> bool:
        """Check if data matches any of the signature patterns."""
        if not self.patterns:
            return False
        
        data_str = data.decode('utf-8', errors='ignore')
        for pattern in self.patterns:
            if pattern in data_str:
                return True
        return False
    
    def __repr__(self) -> str:
        return f"Signature(name='{self.name}', port={self.port}, protocol='{self.protocol}')"


class SignatureDatabase:
    """Database of network service signatures."""
    
    def __init__(self):
        """Initialize an empty signature database."""
        self.signatures: List[Signature] = []
        self._load_default_signatures()
    
    def _load_default_signatures(self):
        """Load default signatures for common network services."""
        default_signatures = [
            Signature("HTTP", 80, "tcp", 
                     patterns=["HTTP/1.1", "HTTP/1.0", "GET ", "POST "],
                     description="Hypertext Transfer Protocol"),
            Signature("HTTPS", 443, "tcp",
                     patterns=["TLS", "SSL"],
                     description="Secure HTTP over TLS/SSL"),
            Signature("SSH", 22, "tcp",
                     patterns=["SSH-2.0", "SSH-1.99"],
                     description="Secure Shell Protocol"),
            Signature("FTP", 21, "tcp",
                     patterns=["220 ", "USER ", "PASS "],
                     description="File Transfer Protocol"),
            Signature("SMTP", 25, "tcp",
                     patterns=["220 ", "EHLO ", "HELO "],
                     description="Simple Mail Transfer Protocol"),
            Signature("DNS", 53, "udp",
                     patterns=[],
                     description="Domain Name System"),
            Signature("MySQL", 3306, "tcp",
                     patterns=[],
                     description="MySQL Database"),
            Signature("PostgreSQL", 5432, "tcp",
                     patterns=[],
                     description="PostgreSQL Database"),
            Signature("Redis", 6379, "tcp",
                     patterns=["+PONG", "-ERR"],
                     description="Redis In-Memory Database"),
            Signature("MongoDB", 27017, "tcp",
                     patterns=[],
                     description="MongoDB NoSQL Database"),
        ]
        
        for sig in default_signatures:
            self.add_signature(sig)
    
    def add_signature(self, signature: Signature):
        """Add a signature to the database."""
        self.signatures.append(signature)
    
    def remove_signature(self, name: str) -> bool:
        """Remove a signature by name. Returns True if removed, False if not found."""
        for i, sig in enumerate(self.signatures):
            if sig.name == name:
                del self.signatures[i]
                return True
        return False
    
    def find_by_port(self, port: int, protocol: str = "tcp") -> List[Signature]:
        """Find all signatures matching the given port and protocol."""
        return [sig for sig in self.signatures if sig.matches_port(port, protocol)]
    
    def find_by_name(self, name: str) -> Optional[Signature]:
        """Find a signature by exact name match."""
        for sig in self.signatures:
            if sig.name == name:
                return sig
        return None
    
    def find_by_pattern(self, data: bytes) -> List[Signature]:
        """Find all signatures matching patterns in the given data."""
        matches = []
        for sig in self.signatures:
            if sig.patterns and sig.matches_pattern(data):
                matches.append(sig)
        return matches
    
    def get_all_signatures(self) -> List[Signature]:
        """Get all signatures in the database."""
        return self.signatures.copy()
    
    def save_to_file(self, filepath: str):
        """Save signatures to a JSON file."""
        data = [sig.to_dict() for sig in self.signatures]
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_from_file(self, filepath: str):
        """Load signatures from a JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.signatures = []
        for sig_data in data:
            self.signatures.append(Signature.from_dict(sig_data))
    
    def __len__(self) -> int:
        return len(self.signatures)
    
    def __repr__(self) -> str:
        return f"SignatureDatabase(signatures={len(self.signatures)})"

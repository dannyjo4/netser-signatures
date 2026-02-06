"""
Network service signature detector.
"""

from typing import Optional, List, Dict, Any
from .signatures import Signature, SignatureDatabase


class DetectionResult:
    """Result of a signature detection."""
    
    def __init__(self, port: int, protocol: str = "tcp"):
        """Initialize detection result."""
        self.port = port
        self.protocol = protocol
        self.matches: List[Signature] = []
        self.confidence: float = 0.0
    
    def add_match(self, signature: Signature, confidence: float = 1.0):
        """Add a matching signature."""
        self.matches.append(signature)
        self.confidence = max(self.confidence, confidence)
    
    def get_best_match(self) -> Optional[Signature]:
        """Get the most likely matching signature."""
        if not self.matches:
            return None
        # For now, just return the first match
        # In a real implementation, this would rank by confidence
        return self.matches[0]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "port": self.port,
            "protocol": self.protocol,
            "matches": [sig.name for sig in self.matches],
            "best_match": self.get_best_match().name if self.get_best_match() else None,
            "confidence": self.confidence
        }
    
    def __repr__(self) -> str:
        return f"DetectionResult(port={self.port}, protocol='{self.protocol}', matches={len(self.matches)})"


class SignatureDetector:
    """Detector for network service signatures."""
    
    def __init__(self, database: Optional[SignatureDatabase] = None):
        """
        Initialize the signature detector.
        
        Args:
            database: SignatureDatabase to use. If None, creates a default one.
        """
        self.database = database or SignatureDatabase()
    
    def detect_by_port(self, port: int, protocol: str = "tcp") -> DetectionResult:
        """
        Detect service by port and protocol.
        
        Args:
            port: Port number
            protocol: Protocol type ("tcp" or "udp")
        
        Returns:
            DetectionResult with matching signatures
        """
        result = DetectionResult(port, protocol)
        matches = self.database.find_by_port(port, protocol)
        
        for match in matches:
            result.add_match(match, confidence=0.7)  # Port-only match has lower confidence
        
        return result
    
    def detect_by_data(self, data: bytes, port: Optional[int] = None, 
                       protocol: str = "tcp") -> DetectionResult:
        """
        Detect service by analyzing data patterns.
        
        Args:
            data: Raw bytes from the service
            port: Optional port number for additional context
            protocol: Protocol type
        
        Returns:
            DetectionResult with matching signatures
        """
        result = DetectionResult(port or 0, protocol)
        pattern_matches = self.database.find_by_pattern(data)
        
        for match in pattern_matches:
            # Pattern match has high confidence
            confidence = 0.95
            # If port also matches, increase confidence
            if port and match.matches_port(port, protocol):
                confidence = 1.0
            result.add_match(match, confidence=confidence)
        
        # If no pattern matches but we have a port, try port-based detection
        if not pattern_matches and port:
            port_matches = self.database.find_by_port(port, protocol)
            for match in port_matches:
                result.add_match(match, confidence=0.5)
        
        return result
    
    def detect(self, port: int, protocol: str = "tcp", 
               data: Optional[bytes] = None) -> DetectionResult:
        """
        Comprehensive detection using both port and data.
        
        Args:
            port: Port number
            protocol: Protocol type
            data: Optional raw bytes from the service
        
        Returns:
            DetectionResult with matching signatures
        """
        if data:
            return self.detect_by_data(data, port, protocol)
        else:
            return self.detect_by_port(port, protocol)
    
    def detect_multiple(self, services: List[Dict[str, Any]]) -> List[DetectionResult]:
        """
        Detect multiple services at once.
        
        Args:
            services: List of dicts with 'port', 'protocol', and optional 'data'
        
        Returns:
            List of DetectionResult objects
        """
        results = []
        for service in services:
            port = service.get('port')
            protocol = service.get('protocol', 'tcp')
            data = service.get('data')
            
            if port:
                result = self.detect(port, protocol, data)
                results.append(result)
        
        return results

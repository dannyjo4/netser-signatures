"""
netser-signatures: Network Service Signature Detection Library

This package provides tools for detecting and identifying network services
based on their signatures (patterns, ports, protocols).
"""

__version__ = "0.1.0"

from .detector import SignatureDetector
from .signatures import Signature, SignatureDatabase

__all__ = ["SignatureDetector", "Signature", "SignatureDatabase"]

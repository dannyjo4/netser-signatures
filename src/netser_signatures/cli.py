"""
Command-line interface for netser-signatures.
"""

import sys
import json
import argparse
from .detector import SignatureDetector
from .signatures import SignatureDatabase


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Network Service Signature Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Detect service by port
  netser-detect --port 80
  
  # Detect service by port and protocol
  netser-detect --port 53 --protocol udp
  
  # List all known signatures
  netser-detect --list
  
  # Show signature details
  netser-detect --info HTTP
        """
    )
    
    parser.add_argument('--port', type=int, help='Port number to detect')
    parser.add_argument('--protocol', default='tcp', choices=['tcp', 'udp'],
                       help='Protocol type (default: tcp)')
    parser.add_argument('--list', action='store_true', 
                       help='List all known signatures')
    parser.add_argument('--info', metavar='NAME',
                       help='Show details for a specific signature')
    parser.add_argument('--json', action='store_true',
                       help='Output in JSON format')
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = SignatureDetector()
    
    # Handle list command
    if args.list:
        signatures = detector.database.get_all_signatures()
        if args.json:
            output = [sig.to_dict() for sig in signatures]
            print(json.dumps(output, indent=2))
        else:
            print(f"Known signatures ({len(signatures)} total):")
            print("-" * 60)
            for sig in signatures:
                print(f"{sig.name:15} {sig.protocol.upper():5} {sig.port:6}  {sig.description}")
        return 0
    
    # Handle info command
    if args.info:
        sig = detector.database.find_by_name(args.info)
        if sig:
            if args.json:
                print(json.dumps(sig.to_dict(), indent=2))
            else:
                print(f"Signature: {sig.name}")
                print(f"Port: {sig.port}")
                print(f"Protocol: {sig.protocol.upper()}")
                print(f"Description: {sig.description}")
                if sig.patterns:
                    print(f"Patterns: {', '.join(sig.patterns)}")
        else:
            print(f"Error: Signature '{args.info}' not found", file=sys.stderr)
            return 1
        return 0
    
    # Handle port detection
    if args.port:
        result = detector.detect_by_port(args.port, args.protocol)
        
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            if result.matches:
                best = result.get_best_match()
                print(f"Port {args.port}/{args.protocol.upper()} detected as:")
                print(f"  Service: {best.name}")
                print(f"  Description: {best.description}")
                print(f"  Confidence: {result.confidence:.0%}")
                
                if len(result.matches) > 1:
                    print(f"\nOther possible matches:")
                    for sig in result.matches[1:]:
                        print(f"  - {sig.name}: {sig.description}")
            else:
                print(f"No known signature for port {args.port}/{args.protocol.upper()}")
        return 0
    
    # No command specified
    parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())

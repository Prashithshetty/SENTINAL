#!/usr/bin/env python
"""
SENTINEL Vulnerability Scanner - Startup Script
Production-ready launcher for the scanner API
"""

import sys
import os
import uvicorn
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

def main():
    """Start the SENTINEL Scanner API server."""
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║       SENTINEL VULNERABILITY SCANNER v2.0                    ║
    ║                                                              ║
    ║     Production-Ready Security Analysis Platform              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    print(" Starting SENTINEL Scanner API Server...")
    print("=" * 60)
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Import settings to validate configuration
    from backend.core.config import settings
    
    print(f" Configuration loaded")
    print(f"   - Debug Mode: {settings.debug}")
    print(f"   - API Host: {settings.api_host}")
    print(f"   - API Port: {settings.api_port}")
    print(f"   - Max Concurrent Scans: {settings.max_concurrent_scans}")
    print(f"   - Rate Limit: {settings.rate_limit_requests_per_minute} req/min")
    print("=" * 60)
    
    # Start the server
    try:
        print("\n Launching API server...")
        print(f" Server will be available at: http://{settings.api_host}:{settings.api_port}")
        print(f" API Documentation: http://{settings.api_host}:{settings.api_port}/docs")
        print(f"  Web Interface: Open frontend/index.html in your browser")
        print("\n⚡ Press CTRL+C to stop the server\n")
        
        uvicorn.run(
            "backend.api.main_simple:app",
            host=settings.api_host,
            port=settings.api_port,
            reload=settings.debug,
            log_level="info" if settings.debug else "warning"
        )
    except KeyboardInterrupt:
        print("\n\n Server stopped by user")
        print(" Thank you for using SENTINEL Scanner!")
    except Exception as e:
        print(f"\n Error starting server: {e}")
        print("Please check your configuration and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main()

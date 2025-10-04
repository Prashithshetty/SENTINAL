"""Simplified API runner for SENTINEL."""

import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

# Create necessary directories
os.makedirs("reports", exist_ok=True)
os.makedirs("scan_results", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# Import and run the API
if __name__ == "__main__":
    import uvicorn
    from backend.api.main import app
    
    print("=" * 60)
    print("SENTINEL Vulnerability Scanner API")
    print("=" * 60)
    print("\nStarting API server...")
    print("API Documentation: http://localhost:8000/docs")
    print("Test Interface: Open frontend/test.html in your browser")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 60)
    
    # Run the server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )

#!/usr/bin/env python3
"""
PathFinder AD — Active Directory Security Assessment
Application entrypoint.
"""

import os
import sys
from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    
    print(f"[*] Starting PathFinder AD on http://{host}:{port}")
    print(f"[*] Safety Mode: Offline Synthetic Analysis Only")
    app.run(host=host, port=port, debug=debug)

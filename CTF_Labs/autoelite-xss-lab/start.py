#!/usr/bin/env python3
"""
AutoElite Motors - Bug Bounty Practice Lab
Quick start script for the XSS practice environment
"""

import subprocess
import sys
import os

def check_python():
    """Check Python version."""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor} detected")

def install_dependencies():
    """Install required packages."""
    print("\n📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "flask"])
        print("✓ Flask installed successfully")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        print("   Try manually: pip install flask")
        sys.exit(1)

def main():
    print("=" * 70)
    print("AutoElite Motors - Bug Bounty Practice Lab")
    print("=" * 70)

    check_python()
    install_dependencies()

    print("\n" + "=" * 70)
    print("🚗 Starting AutoElite Motors Server...")
    print("=" * 70)
    print("\n🌐 Server will run at: http://10.170.65.14:5000")
    print("\n🔑 Admin Credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print("\n🐛 Vulnerabilities to practice:")
    print("   • Blind XSS in contact form")
    print("   • Blind XSS in feedback form")
    print("   • Reflected XSS in search API")
    print("   • Stored XSS in admin panel")
    print("\n⚠️  FOR EDUCATIONAL USE ONLY - DO NOT DEPLOY PUBLICLY")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 70)
    print()

    # Run the Flask app
    try:
        subprocess.run([sys.executable, "app.py"])
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped. Thanks for practicing!")
        sys.exit(0)

if __name__ == "__main__":
    main()

"""
BoltEdge SecToolkit — Application Entry Point

Usage:
    python manage.py              # Run dev server
    python manage.py --port 8000  # Custom port
"""
import argparse
from app import create_app

app = create_app()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecToolkit API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    args = parser.parse_args()

    print(f"\n  🔧 SecToolkit API running at http://{args.host}:{args.port}")
    print(f"  📋 Health check: http://{args.host}:{args.port}/api/health\n")

    app.run(host=args.host, port=args.port, debug=True)
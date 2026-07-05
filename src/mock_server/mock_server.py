#!/usr/bin/env python3
"""
Mock HTTP Server for Vulnerability Verification
================================================
Provides HTTP endpoints that vulnerable extensions may interact with.
Runs on localhost and is managed by verify_extensions.py
"""

from flask import Flask, jsonify, send_file, Response, after_this_request, request
from threading import Thread, Lock
import time
from pathlib import Path
import io
import os
import json
import uuid
import logging

# Disable Flask/Werkzeug request logging
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# Default bind address for the mock server. Kept in sync with config.MOCK_SERVER_HOST/
# MOCK_SERVER_PORT via the same env vars so a single setting drives both this server
# and the verifier's page URL. Read from the env directly (rather than importing
# config) so this module still works when run standalone (`python mock_server.py`).
DEFAULT_HOST = os.getenv("MOCK_SERVER_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("MOCK_SERVER_PORT", "3000"))

app = Flask(__name__)

# =============================================================================
# REQUEST TRACKING (Thread-safe)
# =============================================================================

_request_counts = {
    'api_data': 0,
    'api_file': 0
}
_request_log = []  # Detailed log of all requests with context info
_current_token = str(uuid.uuid4())  # Unique token for current test (initialized on startup)
_request_lock = Lock()

@app.before_request
def track_request():
    """Track incoming requests for verification."""
    with _request_lock:
        if request.path == '/api/data':
            _request_counts['api_data'] += 1
            _request_log.append({
                'path': '/api/data',
                'timestamp': time.time(),
                'extension_id': request.args.get('ext'),  # chrome.runtime.id or 'web'
                'origin': request.headers.get('Origin'),
                'query_params': dict(request.args),
                'method': request.method
            })
        elif request.path == '/api/file':
            _request_counts['api_file'] += 1
            _request_log.append({
                'path': '/api/file',
                'timestamp': time.time(),
                'extension_id': request.args.get('ext'),
                'origin': request.headers.get('Origin'),
                'query_params': dict(request.args),
                'method': request.method
            })

# =============================================================================
# CORS SUPPORT
# =============================================================================

@app.after_request
def add_cors_headers(response):
    """Add CORS headers to all responses for extension access."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Max-Age'] = '3600'
    # Keep connection alive for better compatibility with extensions
    response.headers['Connection'] = 'keep-alive'
    return response

# =============================================================================
# HTTP ENDPOINTS
# =============================================================================

@app.route('/api/data', methods=['GET', 'POST', 'OPTIONS'])
def api_data():
    """API endpoint - returns JSON data that extension may exfiltrate."""
    if request.method == 'OPTIONS':
        return '', 204

    # Include current token for 2way_request verification
    with _request_lock:
        token = _current_token

    # Return explicit Response object with proper headers
    data = json.dumps({
        "data": "exploit",
        "status": "success",
        "token": token
    })
    return Response(
        data,
        mimetype='application/json',
        status=200
    )


@app.route('/api/file', methods=['GET', 'POST', 'OPTIONS'])
def api_file():
    """Download endpoint - returns a file."""
    if request.method == 'OPTIONS':
        return '', 204

    file_obj = io.BytesIO(b"exploit")
    return send_file(
        file_obj,
        as_attachment=True,
        download_name="exploit.txt",
        mimetype="text/plain"
    )


@app.route('/')
def index():
    """Minimal victim page served in local verification mode.

    Replaces the real example.com so the browser has a same-origin local page to
    navigate to. Only used when USE_LOCAL_VERIFICATION_SERVER is enabled; harmless
    otherwise.
    """
    return Response(
        "<!DOCTYPE html><html><head><title>Verification</title></head>"
        "<body><h1>Verification page</h1></body></html>",
        mimetype="text/html",
        status=200,
    )


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"})


@app.route('/api/reset', methods=['POST', 'OPTIONS'])
def reset_counters():
    """Reset request counters, request log, and generate new token - call before each vulnerability test."""
    if request.method == 'OPTIONS':
        return '', 204

    global _current_token, _request_log
    with _request_lock:
        _request_counts['api_data'] = 0
        _request_counts['api_file'] = 0
        _request_log = []  # Clear detailed request log
        _current_token = str(uuid.uuid4())
        token = _current_token

    return jsonify({
        "status": "reset",
        "counts": _request_counts.copy(),
        "token": token
    })


@app.route('/api/requests', methods=['GET', 'OPTIONS'])
def get_requests():
    """Get detailed request log with extension context information."""
    if request.method == 'OPTIONS':
        return '', 204

    with _request_lock:
        requests_copy = list(_request_log)
        # Check if any request came from extension context:
        # - ext parameter set by code_execution payloads (chrome.runtime.id)
        # - Origin header chrome-extension://... set automatically by Chrome for extension requests
        extension_requests = [
            r for r in requests_copy
            if (r.get('extension_id') and r['extension_id'] != 'web')
            or (r.get('origin') or '').startswith('chrome-extension://')
        ]

    return jsonify({
        "status": "ok",
        "requests": requests_copy,
        "total_requests": len(requests_copy),
        "extension_context_requests": len(extension_requests),
        "has_extension_context": len(extension_requests) > 0
    })


@app.route('/api/status', methods=['GET', 'OPTIONS'])
def get_status():
    """Get current request counts."""
    if request.method == 'OPTIONS':
        return '', 204

    with _request_lock:
        counts = _request_counts.copy()

    return jsonify({
        "status": "ok",
        "api_data_requests": counts['api_data'],
        "api_file_requests": counts['api_file']
    })


# =============================================================================
# SERVER MANAGEMENT
# =============================================================================

class MockServer:
    """Manages the mock HTTP server lifecycle."""

    def __init__(self, host: str = DEFAULT_HOST, http_port: int = DEFAULT_PORT):
        self.host = host
        self.http_port = http_port
        self.http_thread = None
        self.is_running = False

    def start(self) -> bool:
        """Start HTTP server in background thread."""
        if self.is_running:
            return True

        try:
            # Start Flask HTTP server in background thread
            self.http_thread = Thread(
                target=lambda: app.run(
                    host=self.host,
                    port=self.http_port,
                    debug=False,
                    use_reloader=False
                ),
                daemon=True
            )
            self.http_thread.start()
            print(f"[HTTP] Server started on http://{self.host}:{self.http_port}")

            # Wait for server to be ready
            time.sleep(1.5)

            self.is_running = True
            return True
        except Exception as e:
            print(f"Failed to start mock server: {e}")
            return False

    def stop(self) -> bool:
        """Stop the mock server."""
        if not self.is_running:
            return True

        try:
            # Flask doesn't have a clean shutdown method in threaded mode,
            # but since it's a daemon thread, it will terminate when main process exits
            self.is_running = False
            return True
        except Exception as e:
            print(f"Failed to stop mock server: {e}")
            return False

    def get_url(self, path: str = "") -> str:
        """Get full URL for an endpoint.

        Args:
            path: The endpoint path (e.g., "/api/data")
        """
        return f"http://{self.host}:{self.http_port}{path}"

    def reset(self) -> bool:
        """Reset request counters before a vulnerability test (legacy method)."""
        try:
            import requests
            response = requests.post(self.get_url("/api/reset"), timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"Failed to reset mock server: {e}")
            return False

    def reset_and_get_token(self) -> str:
        """Reset counters and get unique verification token.

        Returns:
            Unique token string for this test, or None if reset failed
        """
        try:
            import requests
            response = requests.post(self.get_url("/api/reset"), timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('token')
            return None
        except Exception as e:
            print(f"Failed to reset mock server: {e}")
            return None

    def get_request_counts(self) -> dict:
        """Get current request counts from the mock server."""
        try:
            import requests
            response = requests.get(self.get_url("/api/status"), timeout=5)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"Failed to get request counts: {e}")
            return None

    def get_requests(self) -> dict:
        """Get detailed request log with extension context information.

        Returns:
            Dict with:
            - requests: List of request details (path, timestamp, extension_id, query_params)
            - total_requests: Total number of requests
            - extension_context_requests: Number of requests from extension context
            - has_extension_context: True if any request came from extension context
        """
        try:
            import requests
            response = requests.get(self.get_url("/api/requests"), timeout=5)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"Failed to get requests: {e}")
            return None


# Singleton instance
_server_instance = None

def get_mock_server(host: str = DEFAULT_HOST, http_port: int = DEFAULT_PORT) -> MockServer:
    """Get or create the mock server instance.

    Args:
        host: Host to bind to (default: MOCK_SERVER_HOST env or 127.0.0.1)
        http_port: Port for HTTP server (default: MOCK_SERVER_PORT env or 3000)
    """
    global _server_instance
    if _server_instance is None:
        _server_instance = MockServer(host, http_port)
    return _server_instance


if __name__ == "__main__":
    # For testing/manual startup
    server = get_mock_server()
    server.start()
    print(f"\nHTTP Server: {server.get_url()}")
    print("\nPress Ctrl+C to stop...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.stop()

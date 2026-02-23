#!/usr/bin/env python3
"""
Manual Test Script for Mock Server
===================================
Tests HTTP endpoints of the mock server.

Usage:
1. Start the mock server: python src/mock_server/mock_server.py
2. Run this test script: python src/mock_server/test_mock_server.py
"""

import requests
import json

# Server configuration
HTTP_BASE = "http://127.0.0.1:3000"

print("=" * 60)
print("Mock Server Test Suite")
print("=" * 60)
print(f"Testing: HTTP={HTTP_BASE}")
print("=" * 60)

# =============================================================================
# HTTP TESTS
# =============================================================================

print("\n[1] Testing HTTP Endpoints")
print("-" * 60)

# Test 1: Health Check
print("\n1.1 Health Check (GET /health)")
try:
    response = requests.get(f"{HTTP_BASE}/health", timeout=5)
    print(f"✓ Status: {response.status_code}")
    print(f"  Response: {response.json()}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 2: Reset Counters
print("\n1.2 Reset Counters (POST /api/reset)")
try:
    response = requests.post(f"{HTTP_BASE}/api/reset", timeout=5)
    print(f"✓ Status: {response.status_code}")
    print(f"  Response: {response.json()}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 3: Get Status (before any requests)
print("\n1.3 Get Status - Initial (GET /api/status)")
try:
    response = requests.get(f"{HTTP_BASE}/api/status", timeout=5)
    print(f"✓ Status: {response.status_code}")
    print(f"  Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 4: API Data Endpoint
print("\n1.4 API Data Endpoint (GET /api/data)")
try:
    response = requests.get(f"{HTTP_BASE}/api/data", timeout=5)
    print(f"✓ Status: {response.status_code}")
    print(f"  Response: {response.json()}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 5: API Data Endpoint (POST)
print("\n1.5 API Data Endpoint (POST /api/data)")
try:
    response = requests.post(f"{HTTP_BASE}/api/data",
                            json={"test": "payload"},
                            timeout=5)
    print(f"✓ Status: {response.status_code}")
    print(f"  Response: {response.json()}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 6: API File Endpoint
print("\n1.6 API File Endpoint (GET /api/file)")
try:
    response = requests.get(f"{HTTP_BASE}/api/file", timeout=5)
    print(f"✓ Status: {response.status_code}")
    print(f"  Content-Type: {response.headers.get('Content-Type')}")
    print(f"  Content-Disposition: {response.headers.get('Content-Disposition')}")
    print(f"  File Content: {response.content}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 7: Get Status (after HTTP requests)
print("\n1.7 Get Status - After HTTP Requests (GET /api/status)")
try:
    response = requests.get(f"{HTTP_BASE}/api/status", timeout=5)
    print(f"✓ Status: {response.status_code}")
    print(f"  Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"✗ Error: {e}")

# =============================================================================
# FINAL STATUS CHECK
# =============================================================================

print("\n[2] Final Status Check")
print("-" * 60)

print("\n2.1 Get Final Status (GET /api/status)")
try:
    response = requests.get(f"{HTTP_BASE}/api/status", timeout=5)
    print(f"✓ Status: {response.status_code}")
    print(f"  Final Counts:")
    data = response.json()
    print(f"    - HTTP /api/data requests: {data.get('api_data_requests', 0)}")
    print(f"    - HTTP /api/file requests: {data.get('api_file_requests', 0)}")
except Exception as e:
    print(f"✗ Error: {e}")

print("\n" + "=" * 60)
print("Test Suite Complete")
print("=" * 60)

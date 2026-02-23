"""
Mock Server Package
===================
Provides HTTP and WebSocket mock servers for vulnerability verification.
"""

from .mock_server import get_mock_server, MockServer

__all__ = ['get_mock_server', 'MockServer']

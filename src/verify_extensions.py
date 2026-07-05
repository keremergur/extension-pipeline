#!/usr/bin/env python3
"""
Chrome Extension Vulnerability Verification — entry point.

The implementation now lives in the `verifier/` package. This shim preserves
the `python verify_extensions.py` invocation.
"""
import asyncio
from verifier.main import main

if __name__ == "__main__":
    asyncio.run(main())

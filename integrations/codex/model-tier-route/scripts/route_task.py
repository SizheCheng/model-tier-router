#!/usr/bin/env python3
"""Invoke the supported advisory CLI for one stdin request."""

from __future__ import annotations

from model_tier_router.cli import main


if __name__ == "__main__":
    raise SystemExit(main(["assess"]))

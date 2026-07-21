"""Stable public entrypoint for manifest-driven single-product execution."""

from .remaining_lane_execution import build_parser, main, run, self_test

__all__ = ["build_parser", "main", "run", "self_test"]

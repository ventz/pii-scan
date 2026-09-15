"""Detectors turn text into Spans. Every detector raises on failure; none returns [] on error."""

from .base import Detector, DetectorError

__all__ = ["Detector", "DetectorError"]

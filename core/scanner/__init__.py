#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Scanner Module
Provides scanning capabilities for malware detection
"""

from .quick_scan import run_quick_scan
from .deep_scan import run_deep_scan
from .custom_scan import run_custom_scan

__all__ = ['run_quick_scan', 'run_deep_scan', 'run_custom_scan']
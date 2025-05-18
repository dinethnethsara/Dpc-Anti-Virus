#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Core Module
Provides the core functionality for the antivirus software
"""

# Import submodules
from . import scanner
from . import detection

__all__ = ['scanner', 'detection']
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Quick Scan Module
Performs a fast scan of critical system areas for malware detection
"""

import os
import sys
import time
import logging
from datetime import datetime

# Setup logging
logger = logging.getLogger('dpc_sentinel_x.scanner.quick_scan')

# Critical paths to scan (Windows-specific)
CRITICAL_PATHS = [
    os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'),
    os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'),
    os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    os.path.join(os.environ.get('TEMP', ''), ''),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
]

# File extensions commonly associated with malware
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.pif'
]


def run_quick_scan():
    """
    Run a quick scan of critical system areas
    Returns a tuple of (scan_results, scan_stats)
    """
    logger.info("Starting Quick Scan")
    print("\nDPC Sentinel X - Quick Scan")
    print("---------------------------")
    
    start_time = time.time()
    scan_results = []
    scan_stats = {
        'files_scanned': 0,
        'suspicious_files': 0,
        'errors': 0,
        'start_time': datetime.now(),
        'end_time': None,
        'duration': 0
    }
    
    try:
        # Scan critical paths
        for path in CRITICAL_PATHS:
            if os.path.exists(path):
                print(f"Scanning {path}...")
                _scan_directory(path, scan_results, scan_stats, max_depth=2)
            else:
                logger.warning(f"Path not found: {path}")
                print(f"Warning: Path not found: {path}")
        
        # Complete scan stats
        scan_stats['end_time'] = datetime.now()
        scan_stats['duration'] = time.time() - start_time
        
        # Display results
        print("\nScan Complete!")
        print(f"Duration: {scan_stats['duration']:.2f} seconds")
        print(f"Files Scanned: {scan_stats['files_scanned']}")
        print(f"Suspicious Files: {scan_stats['suspicious_files']}")
        print(f"Errors: {scan_stats['errors']}")
        
        if scan_stats['suspicious_files'] > 0:
            print("\nSuspicious files found:")
            for result in scan_results:
                if result['status'] == 'suspicious':
                    print(f" - {result['file_path']} ({result['reason']})")
        
        return scan_results, scan_stats
    
    except Exception as e:
        logger.error(f"Error during quick scan: {e}", exc_info=True)
        print(f"Error during scan: {e}")
        scan_stats['end_time'] = datetime.now()
        scan_stats['duration'] = time.time() - start_time
        return scan_results, scan_stats


def _scan_directory(directory, results, stats, max_depth=3, current_depth=0):
    """
    Recursively scan a directory for suspicious files
    """
    if current_depth > max_depth:
        return
    
    try:
        for entry in os.scandir(directory):
            try:
                # Skip if symlink
                if entry.is_symlink():
                    continue
                
                # Process file
                if entry.is_file():
                    stats['files_scanned'] += 1
                    
                    # Check if file extension is suspicious
                    _, ext = os.path.splitext(entry.name.lower())
                    if ext in SUSPICIOUS_EXTENSIONS:
                        # In a real implementation, we would perform deeper analysis here
                        # For now, just flag files with suspicious extensions
                        results.append({
                            'file_path': entry.path,
                            'status': 'suspicious',
                            'reason': f'Suspicious extension: {ext}',
                            'timestamp': datetime.now()
                        })
                        stats['suspicious_files'] += 1
                        logger.warning(f"Suspicious file found: {entry.path}")
                
                # Process subdirectory
                elif entry.is_dir():
                    _scan_directory(entry.path, results, stats, max_depth, current_depth + 1)
            
            except Exception as e:
                logger.error(f"Error scanning {entry.path}: {e}")
                stats['errors'] += 1
    
    except Exception as e:
        logger.error(f"Error accessing directory {directory}: {e}")
        stats['errors'] += 1


# For testing purposes
if __name__ == "__main__":
    # Setup console logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    
    # Run quick scan
    run_quick_scan()
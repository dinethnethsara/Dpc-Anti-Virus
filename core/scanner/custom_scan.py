#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Custom Scan Module
Performs a scan of user-specified locations for malware detection
"""

import os
import sys
import time
import logging
import hashlib
from datetime import datetime

# Setup logging
logger = logging.getLogger('dpc_sentinel_x.scanner.custom_scan')

# File extensions to scan
TARGET_EXTENSIONS = [
    # Executables
    '.exe', '.dll', '.sys', '.drv', '.ocx', '.cpl',
    # Scripts
    '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.wsf', '.wsh', '.hta',
    # Java
    '.jar', '.class',
    # Office macros
    '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm',
    # Other
    '.scr', '.pif', '.msi', '.com'
]


def run_custom_scan(target_path):
    """
    Run a custom scan on a user-specified path
    
    Args:
        target_path (str): Path to scan
        
    Returns:
        tuple: (scan_results, scan_stats)
    """
    if not target_path or not os.path.exists(target_path):
        print(f"Error: Path '{target_path}' does not exist.")
        return [], {}
    
    logger.info(f"Starting Custom Scan on {target_path}")
    print(f"\nDPC Sentinel X - Custom Scan: {target_path}")
    print("------------------------------------------")
    
    start_time = time.time()
    scan_results = []
    scan_stats = {
        'files_scanned': 0,
        'suspicious_files': 0,
        'start_time': datetime.now(),
        'end_time': None,
        'duration': 0,
        'target_path': target_path
    }
    
    try:
        # Check if target is a file or directory
        if os.path.isfile(target_path):
            print(f"Scanning file: {target_path}")
            scan_stats['files_scanned'] += 1
            _analyze_file(target_path, scan_results, scan_stats)
        else:
            print(f"Scanning directory: {target_path}")
            _scan_directory(target_path, scan_results, scan_stats)
        
        # Complete scan stats
        scan_stats['end_time'] = datetime.now()
        scan_stats['duration'] = time.time() - start_time
        
        # Display results
        print("\nScan Complete!")
        print(f"Duration: {_format_duration(scan_stats['duration'])}")
        print(f"Files Scanned: {scan_stats['files_scanned']}")
        print(f"Suspicious Files: {scan_stats['suspicious_files']}")
        
        if scan_stats['suspicious_files'] > 0:
            print("\nSuspicious files found:")
            for result in scan_results:
                if result['status'] == 'suspicious':
                    print(f" - {result['file_path']}")
                    print(f"   Reason: {result['reason']}")
                    print(f"   SHA256: {result.get('sha256', 'N/A')}")
                    print()
        
        return scan_results, scan_stats
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        logger.info("Custom scan interrupted by user")
        scan_stats['end_time'] = datetime.now()
        scan_stats['duration'] = time.time() - start_time
        return scan_results, scan_stats
    
    except Exception as e:
        logger.error(f"Error during custom scan: {e}", exc_info=True)
        print(f"\nError during scan: {e}")
        scan_stats['end_time'] = datetime.now()
        scan_stats['duration'] = time.time() - start_time
        return scan_results, scan_stats


def _scan_directory(directory, results, stats, max_depth=10, current_depth=0):
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
                    
                    # Update progress periodically
                    if stats['files_scanned'] % 100 == 0:
                        print(f"Files scanned: {stats['files_scanned']}")
                    
                    # Check if file extension is in target list
                    _, ext = os.path.splitext(entry.name.lower())
                    if ext in TARGET_EXTENSIONS:
                        # Perform deeper analysis
                        _analyze_file(entry.path, results, stats)
                
                # Process subdirectory
                elif entry.is_dir():
                    _scan_directory(entry.path, results, stats, max_depth, current_depth + 1)
            
            except Exception as e:
                logger.error(f"Error scanning {entry.path}: {e}")
                print(f"Error scanning {entry.path}: {e}")
    
    except Exception as e:
        logger.error(f"Error accessing directory {directory}: {e}")
        print(f"Error accessing directory {directory}: {e}")


def _analyze_file(file_path, results, stats):
    """
    Perform detailed analysis on a file
    """
    try:
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Skip very large files
        if file_size > 100 * 1024 * 1024:  # 100 MB
            logger.info(f"Skipping large file: {file_path} ({file_size} bytes)")
            return
        
        # Calculate file hash
        sha256_hash = _calculate_sha256(file_path)
        
        # Perform heuristic analysis (simplified for this example)
        suspicious = False
        reason = []
        
        # Check file size (some malware is very small)
        if file_size < 1024 and file_path.lower().endswith('.exe'):
            suspicious = True
            reason.append("Unusually small executable")
        
        # Check file name for suspicious patterns
        filename = os.path.basename(file_path).lower()
        suspicious_names = ['trojan', 'hack', 'crack', 'keygen', 'patch', 'warez', 'virus']
        for name in suspicious_names:
            if name in filename:
                suspicious = True
                reason.append(f"Suspicious filename pattern: {name}")
        
        # In a real implementation, we would perform more sophisticated analysis here
        # Such as checking for PE header anomalies, entropy analysis, etc.
        
        # If suspicious, add to results
        if suspicious:
            results.append({
                'file_path': file_path,
                'status': 'suspicious',
                'reason': ', '.join(reason),
                'sha256': sha256_hash,
                'size': file_size,
                'timestamp': datetime.now()
            })
            stats['suspicious_files'] += 1
            logger.warning(f"Suspicious file found: {file_path}")
    
    except Exception as e:
        logger.error(f"Error analyzing file {file_path}: {e}")


def _calculate_sha256(file_path):
    """
    Calculate SHA256 hash of a file
    """
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating SHA256 for {file_path}: {e}")
        return ""


def _format_duration(seconds):
    """
    Format duration in seconds to a human-readable string
    """
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


# For testing purposes
if __name__ == "__main__":
    # Setup console logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    
    # Get path from command line argument or use current directory
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = os.getcwd()
    
    # Run custom scan
    run_custom_scan(path)
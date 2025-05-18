#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Signature Detection Module
Provides functionality for detecting malware based on known signatures
"""

from typing import List, Dict, Optional
import hashlib
import os

class SignatureDetector:
    def __init__(self):
        self.signature_db: Dict[str, str] = {}
        self.initialize_signatures()
    
    def initialize_signatures(self) -> None:
        """Initialize the signature database with known malware signatures."""
        # TODO: In production, load from a secure signature database
        # For now, using a small sample set
        self.signature_db = {
            # MD5 signatures of known malware samples
            "44d88612fea8a8f36de82e1278abb02f": "Trojan.Generic",
            "81891b0d3cbb89c1e044b8c5c504c83a": "Worm.Win32",
            "e6d290a03b70cfa5d4451da444bdea39": "Ransomware.Crypto"
        }
    
    def calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate MD5 hash of a file."""
        try:
            with open(file_path, 'rb') as f:
                md5_hash = hashlib.md5()
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
                return md5_hash.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {file_path}: {str(e)}")
            return None
    
    def scan_file(self, file_path: str) -> Dict[str, str]:
        """Scan a single file for known malware signatures."""
        result = {
            "file_path": file_path,
            "status": "clean",
            "threat_name": None
        }
        
        file_hash = self.calculate_file_hash(file_path)
        if not file_hash:
            result["status"] = "error"
            return result
            
        if file_hash in self.signature_db:
            result["status"] = "infected"
            result["threat_name"] = self.signature_db[file_hash]
            
        return result
    
    def scan_directory(self, directory_path: str) -> List[Dict[str, str]]:
        """Recursively scan a directory for known malware signatures."""
        results = []
        try:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    results.append(self.scan_file(file_path))
        except Exception as e:
            print(f"Error scanning directory {directory_path}: {str(e)}")
        return results

# Create a global instance for easy access
signature_detector = SignatureDetector()

def scan_file(file_path: str) -> Dict[str, str]:
    """Convenience function to scan a single file."""
    return signature_detector.scan_file(file_path)

def scan_directory(directory_path: str) -> List[Dict[str, str]]:
    """Convenience function to scan a directory."""
    return signature_detector.scan_directory(directory_path)
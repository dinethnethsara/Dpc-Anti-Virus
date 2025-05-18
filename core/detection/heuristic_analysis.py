#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Heuristic Analysis Module
Provides functionality for detecting malware using behavioral and pattern analysis
"""

from typing import Dict, List, Set
import os
import re

class HeuristicAnalyzer:
    def __init__(self):
        self.suspicious_patterns: Dict[str, int] = {
            # System modification patterns
            r"registry\.SetValue": 3,
            r"Process\.Start": 2,
            r"File\.Delete": 2,
            
            # Network activity patterns
            r"Socket\.Connect": 2,
            r"Http(Client|Request)": 2,
            
            # Encryption patterns
            r"Crypto(stream|provider)": 3,
            r"Rijndael|AES|RSA": 3,

            # Process injection patterns
            r"WriteProcessMemory": 4,
            r"CreateRemoteThread": 4,
            r"NtCreateThreadEx": 4,

            # Code obfuscation patterns
            r"VirtualAllocEx": 3,
            r"VirtualProtectEx": 3,

            # Persistence mechanisms
            r"Run\s*=": 3, # Registry Run key
            r"StartupFolder": 3, # Windows Startup folder

            # File operation patterns
            r"\.exe|\.dll|\.sys": 1,
            r"CreateFile|WriteFile": 2
        }
        
        self.risk_threshold = 5
    
    def analyze_file_content(self, file_path: str) -> Dict[str, any]:
        """Analyze file content for suspicious patterns."""
        result = {
            "file_path": file_path,
            "risk_score": 0,
            "detected_patterns": set(),
            "risk_level": "low"
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
                
                # Check for suspicious patterns
                for pattern, score in self.suspicious_patterns.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        result["risk_score"] += score
                        result["detected_patterns"].add(pattern)
                
                # Determine risk level
                if result["risk_score"] >= self.risk_threshold:
                    result["risk_level"] = "high"
                elif result["risk_score"] >= self.risk_threshold // 2:
                    result["risk_level"] = "medium"
                
                # Convert set to list for JSON serialization
                result["detected_patterns"] = list(result["detected_patterns"])
                
        except Exception as e:
            print(f"Error analyzing file {file_path}: {str(e)}")
            result["error"] = str(e)
        
        return result
    
    def analyze_file_attributes(self, file_path: str) -> Dict[str, any]:
        """Analyze file attributes for suspicious characteristics."""
        result = {
            "file_path": file_path,
            "suspicious_attributes": []
        }
        
        try:
            # Check file attributes
            stats = os.stat(file_path)
            
            # Check for hidden files
            if os.path.basename(file_path).startswith('.'):
                result["suspicious_attributes"].append("hidden_file")
            
            # Check for unusual permissions
            if stats.st_mode & 0o777 == 0o777:
                result["suspicious_attributes"].append("full_permissions")
            
            # Check file size (empty or very small executables are suspicious)
            if file_path.endswith(('.exe', '.dll')) and stats.st_size < 1024:
                result["suspicious_attributes"].append("suspicious_size")
                
        except Exception as e:
            print(f"Error checking file attributes {file_path}: {str(e)}")
            result["error"] = str(e)
        
        return result

    def analyze_directory(self, directory_path: str) -> List[Dict[str, any]]:
        """Recursively analyze files in a directory."""
        results = []
        try:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    content_analysis = self.analyze_file_content(file_path)
                    attribute_analysis = self.analyze_file_attributes(file_path)
                    
                    # Combine analyses
                    combined_result = {
                        "file_path": file_path,
                        "content_analysis": content_analysis,
                        "attribute_analysis": attribute_analysis
                    }
                    results.append(combined_result)
                    
        except Exception as e:
            print(f"Error analyzing directory {directory_path}: {str(e)}")
            
        return results

# Create a global instance for easy access
heuristic_analyzer = HeuristicAnalyzer()

def analyze_file(file_path: str) -> Dict[str, any]:
    """Convenience function to analyze a single file."""
    content_analysis = heuristic_analyzer.analyze_file_content(file_path)
    attribute_analysis = heuristic_analyzer.analyze_file_attributes(file_path)
    return {
        "file_path": file_path,
        "content_analysis": content_analysis,
        "attribute_analysis": attribute_analysis
    }

def analyze_directory(directory_path: str) -> List[Dict[str, any]]:
    """Convenience function to analyze a directory."""
    return heuristic_analyzer.analyze_directory(directory_path)
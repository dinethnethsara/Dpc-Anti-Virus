#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Real-time System Monitoring Module
Provides real-time system monitoring and threat detection capabilities
"""

import os
import time
import psutil
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal

@dataclass
class SystemMetrics:
    cpu_usage: float
    memory_usage: float
    disk_io: Dict[str, float]
    network_io: Dict[str, float]
    active_processes: int
    timestamp: datetime

class SystemMonitor(QObject):
    metrics_updated = pyqtSignal(dict)
    threat_detected = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.baseline_metrics = None
        self.anomaly_thresholds = {
            'cpu_spike': 85.0,  # CPU usage threshold
            'memory_spike': 90.0,  # Memory usage threshold
            'io_spike': 80.0,  # I/O activity threshold
            'network_spike': 75.0  # Network activity threshold
        }
    
    def start_monitoring(self):
        """Start real-time system monitoring"""
        self.baseline_metrics = self._collect_system_metrics()
        # Implementation would continue with actual monitoring loop
    
    def _collect_system_metrics(self) -> SystemMetrics:
        """Collect current system metrics"""
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk_io = psutil.disk_io_counters(perdisk=True)
        network_io = psutil.net_io_counters()
        
        return SystemMetrics(
            cpu_usage=cpu_usage,
            memory_usage=memory.percent,
            disk_io={'read': disk_io.read_bytes, 'write': disk_io.write_bytes},
            network_io={'sent': network_io.bytes_sent, 'recv': network_io.bytes_recv},
            active_processes=len(psutil.process_iter()),
            timestamp=datetime.now()
        )
    
    def _detect_anomalies(self, current_metrics: SystemMetrics) -> List[Dict]:
        """Detect system anomalies by comparing with baseline"""
        anomalies = []
        
        # Check CPU usage
        if current_metrics.cpu_usage > self.anomaly_thresholds['cpu_spike']:
            anomalies.append({
                'type': 'cpu_anomaly',
                'value': current_metrics.cpu_usage,
                'threshold': self.anomaly_thresholds['cpu_spike'],
                'timestamp': current_metrics.timestamp
            })
        
        # Check memory usage
        if current_metrics.memory_usage > self.anomaly_thresholds['memory_spike']:
            anomalies.append({
                'type': 'memory_anomaly',
                'value': current_metrics.memory_usage,
                'threshold': self.anomaly_thresholds['memory_spike'],
                'timestamp': current_metrics.timestamp
            })
        
        return anomalies
    
    def _analyze_process_behavior(self) -> List[Dict]:
        """Analyze running processes for suspicious behavior"""
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                # Check for high resource usage
                is_suspicious = False
                reasons = []

                if proc.info['cpu_percent'] > 50 or proc.info['memory_percent'] > 50:
                    is_suspicious = True
                    reasons.append('high resource usage')

                # Check for unusual process location (basic check)
                try:
                    exe_path = proc.exe()
                    unusual_locations = ['temp', 'tmp', 'appdata', 'local', 'roaming'] # Common malware locations
                    if any(loc in exe_path.lower() for loc in unusual_locations):
                         is_suspicious = True
                         reasons.append('unusual execution path')
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass # Ignore if path is not accessible

                # Check for suspicious command-line arguments (basic patterns)
                try:
                    cmdline = " ".join(proc.cmdline()).lower()
                    suspicious_args = ['powershell -encodedcommand', 'cmd /c', '/c', '/k', 'hidden', 'windowstyle hidden']
                    if any(arg in cmdline for arg in suspicious_args):
                        is_suspicious = True
                        reasons.append('suspicious command line arguments')
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass # Ignore if cmdline is not accessible

                if is_suspicious:
                    suspicious_processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cpu_usage': proc.info['cpu_percent'],
                        'memory_usage': proc.info['memory_percent'],
                        'reasons': reasons,
                        'timestamp': datetime.now()
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return suspicious_processes
    
    def update_thresholds(self, new_thresholds: Dict[str, float]):
        """Update anomaly detection thresholds"""
        self.anomaly_thresholds.update(new_thresholds)
    
    def get_system_health(self) -> Dict:
        """Get current system health status"""
        metrics = self._collect_system_metrics()
        anomalies = self._detect_anomalies(metrics)
        suspicious_processes = self._analyze_process_behavior()
        
        return {
            'metrics': {
                'cpu_usage': metrics.cpu_usage,
                'memory_usage': metrics.memory_usage,
                'disk_io': metrics.disk_io,
                'network_io': metrics.network_io,
                'active_processes': metrics.active_processes
            },
            'anomalies': anomalies,
            'suspicious_processes': suspicious_processes,
            'timestamp': metrics.timestamp.isoformat()
        }
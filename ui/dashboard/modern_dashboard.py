#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Modern Dashboard Component
Provides an enhanced dashboard with glass morphism effects and real-time monitoring
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QProgressBar, QStackedWidget
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QIcon
from .glass_morphism import GlassEffect, ModernAnimation
from .theme_manager import ThemeManager
from core.monitoring.realtime_monitor import SystemMonitor
from core.protection.ransomware_protection import RansomwareProtection
from core.detection.advanced_detection import AdvancedDetectionEngine

class ModernDashboard(QWidget):
    update_required = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.theme_manager = ThemeManager()
        self.system_monitor = SystemMonitor()
        self.ransomware_protection = RansomwareProtection()
        self.detection_engine = AdvancedDetectionEngine()
        
        # Setup UI
        self._init_ui()
        self._setup_animations()
        self._connect_signals()
        
        # Start monitoring
        self._start_monitoring()
    
    def _init_ui(self):
        """Initialize the modern dashboard UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Status Overview Section
        status_frame = QFrame()
        status_frame.setGraphicsEffect(GlassEffect())
        status_frame.setStyleSheet(self.theme_manager.get_glass_style())
        status_layout = QHBoxLayout(status_frame)
        
        # System Health Widget
        self.health_widget = self._create_health_widget()
        status_layout.addWidget(self.health_widget)
        
        # Protection Status Widget
        self.protection_widget = self._create_protection_widget()
        status_layout.addWidget(self.protection_widget)
        
        layout.addWidget(status_frame)
        
        # Real-time Monitoring Section
        monitoring_frame = QFrame()
        monitoring_frame.setGraphicsEffect(GlassEffect())
        monitoring_frame.setStyleSheet(self.theme_manager.get_glass_style())
        monitoring_layout = QVBoxLayout(monitoring_frame)
        
        # Resource Usage
        self.cpu_bar = self._create_resource_bar("CPU Usage")
        self.memory_bar = self._create_resource_bar("Memory Usage")
        self.disk_bar = self._create_resource_bar("Disk I/O")
        
        monitoring_layout.addWidget(self.cpu_bar)
        monitoring_layout.addWidget(self.memory_bar)
        monitoring_layout.addWidget(self.disk_bar)
        
        layout.addWidget(monitoring_frame)
        
        # Threat Detection Section
        threat_frame = QFrame()
        threat_frame.setGraphicsEffect(GlassEffect())
        threat_frame.setStyleSheet(self.theme_manager.get_glass_style())
        threat_layout = QVBoxLayout(threat_frame)
        
        self.threat_stack = QStackedWidget()
        self.threat_summary = self._create_threat_summary()
        self.threat_details = self._create_threat_details()
        
        self.threat_stack.addWidget(self.threat_summary)
        self.threat_stack.addWidget(self.threat_details)
        threat_layout.addWidget(self.threat_stack)
        
        layout.addWidget(threat_frame)
    
    def _create_health_widget(self) -> QFrame:
        """Create system health status widget"""
        frame = QFrame()
        layout = QVBoxLayout(frame)
        
        title = QLabel("System Health")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        layout.addWidget(title)
        
        self.health_status = QLabel("Healthy")
        self.health_status.setStyleSheet(f"color: {self.theme_manager.get_theme_colors().success};")
        layout.addWidget(self.health_status)
        
        return frame
    
    def _create_protection_widget(self) -> QFrame:
        """Create protection status widget"""
        frame = QFrame()
        layout = QVBoxLayout(frame)
        
        title = QLabel("Protection Status")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        layout.addWidget(title)
        
        self.protection_status = QLabel("Active")
        self.protection_status.setStyleSheet(f"color: {self.theme_manager.get_theme_colors().success};")
        layout.addWidget(self.protection_status)
        
        return frame
    
    def _create_resource_bar(self, label: str) -> QWidget:
        """Create a resource usage progress bar"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        
        label = QLabel(label)
        label.setFixedWidth(100)
        layout.addWidget(label)
        
        progress = QProgressBar()
        progress.setTextVisible(True)
        progress.setStyleSheet("""
            QProgressBar {
                border: none;
                border-radius: 5px;
                text-align: center;
                background: rgba(255, 255, 255, 0.1);
            }
            QProgressBar::chunk {
                border-radius: 5px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2196F3, stop:1 #64B5F6);
            }
        """)
        layout.addWidget(progress)
        
        return widget
    
    def _create_threat_summary(self) -> QWidget:
        """Create threat detection summary widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        title = QLabel("Threat Summary")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        layout.addWidget(title)
        
        self.threats_detected = QLabel("No threats detected")
        layout.addWidget(self.threats_detected)
        
        return widget
    
    def _create_threat_details(self) -> QWidget:
        """Create detailed threat information widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        title = QLabel("Threat Details")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        layout.addWidget(title)
        
        self.threat_info = QLabel()
        layout.addWidget(self.threat_info)
        
        return widget
    
    def _setup_animations(self):
        """Setup UI animations"""
        self.fade_animation = ModernAnimation.fade_in(self)
        self.slide_animation = ModernAnimation.slide_in(self)
    
    def _connect_signals(self):
        """Connect signal handlers"""
        self.system_monitor.metrics_updated.connect(self._update_system_metrics)
        self.ransomware_protection.attack_detected.connect(self._handle_ransomware_alert)
        self.detection_engine.threat_detected.connect(self._handle_threat_alert)
    
    def _start_monitoring(self):
        """Start real-time monitoring"""
        self.system_monitor.start_monitoring()
        self.ransomware_protection.start_protection()
        
        # Update UI periodically
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._refresh_ui)
        self.update_timer.start(1000)  # Update every second
    
    def _update_system_metrics(self, metrics: dict):
        """Update system metrics display"""
        self.cpu_bar.findChild(QProgressBar).setValue(int(metrics['cpu_usage']))
        self.memory_bar.findChild(QProgressBar).setValue(int(metrics['memory_usage']))
        
        # Update health status based on metrics
        if metrics['cpu_usage'] > 90 or metrics['memory_usage'] > 90:
            self.health_status.setText("Warning")
            self.health_status.setStyleSheet(f"color: {self.theme_manager.get_theme_colors().warning};")
        else:
            self.health_status.setText("Healthy")
            self.health_status.setStyleSheet(f"color: {self.theme_manager.get_theme_colors().success};")
    
    def _handle_ransomware_alert(self, alert: dict):
        """Handle ransomware detection alert"""
        self.threats_detected.setText(f"Ransomware Activity Detected!")
        self.threats_detected.setStyleSheet(f"color: {self.theme_manager.get_theme_colors().danger};")
        self.threat_info.setText(f"Suspicious activity: {alert['details']}")
        self.threat_stack.setCurrentIndex(1)  # Show details
        self.update_required.emit(alert)
    
    def _handle_threat_alert(self, alert: dict):
        """Handle general threat detection alert"""
        self.threats_detected.setText(f"Threat Detected: {alert['type']}")
        self.threats_detected.setStyleSheet(f"color: {self.theme_manager.get_theme_colors().danger};")
        self.threat_info.setText(f"Risk Level: {alert['risk_level']}\nDetails: {alert['description']}")
        self.threat_stack.setCurrentIndex(1)  # Show details
        self.update_required.emit(alert)
    
    def _refresh_ui(self):
        """Refresh UI components"""
        protection_stats = self.ransomware_protection.get_protection_stats()
        detection_stats = self.detection_engine.get_detection_stats()
        
        # Update protection status
        if protection_stats['attacks_blocked'] > 0:
            self.protection_status.setText(f"Active (Threats Blocked: {protection_stats['attacks_blocked']})")
        
        # Animate threat stack if needed
        if self.threat_stack.currentIndex() == 1:
            self.slide_animation.start()
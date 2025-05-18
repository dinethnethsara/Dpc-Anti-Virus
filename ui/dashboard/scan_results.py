#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Scan Results UI Component
Provides the UI components for displaying scan results and threat analysis
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QFrame, QScrollArea, QStackedWidget,
    QProgressBar, QComboBox
)
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPalette, QIcon
from .styles import UIStyles

class ScanResultsWidget(QWidget):
    scan_completed = pyqtSignal(dict)
    threat_detected = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.dark_mode = False
        self.theme_colors = UIStyles.get_theme_colors(self.dark_mode)
        self._init_ui()
        self._setup_animations()
        
    def toggle_theme(self):
        """Toggle between light and dark theme"""
        self.dark_mode = not self.dark_mode
        self.theme_colors = UIStyles.get_theme_colors(self.dark_mode)
        self._apply_theme()
        
    def _setup_animations(self):
        """Setup UI animations"""
        self.stats_animation = QPropertyAnimation(self.stats_frame, b'geometry')
        self.stats_animation.setDuration(UIStyles.ANIMATION_DURATION)
        self.stats_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    
    def _init_ui(self):
        """Initialize the scan results UI"""
        layout = QVBoxLayout(self)
        
        # Create header
        header_frame = QFrame()
        header_frame.setStyleSheet(UIStyles.HEADER_STYLE.format(**self.theme_colors))
        header_layout = QHBoxLayout(header_frame)
        
        self.scan_type_label = QLabel("Scan Results")
        self.scan_type_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        header_layout.addWidget(self.scan_type_label)
        
        self.scan_time_label = QLabel()
        header_layout.addWidget(self.scan_time_label, alignment=Qt.AlignmentFlag.AlignRight)
        
        layout.addWidget(header_frame)
        
        # Create statistics section
        stats_frame = QFrame()
        self.stats_frame = stats_frame
        stats_frame.setStyleSheet(UIStyles.STATS_WIDGET_STYLE.format(**self.theme_colors))
        stats_layout = QHBoxLayout(stats_frame)
        
        # Files scanned
        files_stats = self._create_stat_widget(
            "Files Scanned",
            "0",
            "#2196F3"
        )
        stats_layout.addWidget(files_stats)
        
        # Threats found
        threats_stats = self._create_stat_widget(
            "Threats Found",
            "0",
            "#F44336"
        )
        stats_layout.addWidget(threats_stats)
        
        # Time elapsed
        time_stats = self._create_stat_widget(
            "Time Elapsed",
            "0:00",
            "#4CAF50"
        )
        stats_layout.addWidget(time_stats)
        
        layout.addWidget(stats_frame)
        
        # Create results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setStyleSheet(UIStyles.TABLE_STYLE.format(**self.theme_colors))
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels([
            "File", "Status", "Threat Type", "Risk Level", "Detection Method", "Details", "Action"
        ])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.results_table)
        
        # Create action buttons
        action_layout = QHBoxLayout()
        
        self.quarantine_btn = QPushButton("Quarantine Selected")
        self.quarantine_btn.setStyleSheet(UIStyles.BUTTON_STYLE.format(**self.theme_colors))
        self.quarantine_btn.setEnabled(False)
        action_layout.addWidget(self.quarantine_btn)
        
        self.delete_btn = QPushButton("Delete Selected")
        self.delete_btn.setStyleSheet(UIStyles.BUTTON_STYLE.format(**self.theme_colors))
        self.delete_btn.setEnabled(False)
        action_layout.addWidget(self.delete_btn)
        
        self.ignore_btn = QPushButton("Ignore Selected")
        self.ignore_btn.setStyleSheet(UIStyles.BUTTON_STYLE.format(**self.theme_colors))
        self.ignore_btn.setEnabled(False)
        action_layout.addWidget(self.ignore_btn)
        
        action_layout.addStretch()
        
        self.export_btn = QPushButton("Export Results")
        self.export_btn.setStyleSheet(UIStyles.BUTTON_STYLE.format(**self.theme_colors))
        action_layout.addWidget(self.export_btn)
        
        layout.addLayout(action_layout)
    
    def _create_stat_widget(self, title, value, color):
        """Create a statistics widget with title and value"""
        widget = QFrame()
        widget.setStyleSheet(f"border: 2px solid {color}; border-radius: 5px; padding: 10px;")
        layout = QVBoxLayout(widget)
        
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {color}; border: none;")
        title_label.setFont(QFont("Arial", 10))
        layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setStyleSheet("border: none;")
        value_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(value_label)
        
        return widget
    
    def update_results(self, results, stats):
        """Update the scan results display
        
        Args:
            results (list): List of scan results
            stats (dict): Scan statistics
        """
        # Update statistics
        self._update_statistics(stats)
        
        # Clear existing results
        self.results_table.setRowCount(0)
        
        # Add new results
        for result in results:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            # File path
            self.results_table.setItem(row, 0, QTableWidgetItem(result.get('file_path', '')))
            
            # Status
            status = result.get('status', 'unknown')
            status_item = QTableWidgetItem(status)
            status_item.setForeground(
                QColor('#F44336') if status == 'infected' else
                QColor('#FF9800') if status == 'suspicious' else
                QColor('#4CAF50')
            )
            self.results_table.setItem(row, 1, status_item)
            
            # Threat type
            self.results_table.setItem(row, 2, QTableWidgetItem(result.get('threat_name', '')))
            
            # Risk level
            risk_level = result.get('risk_level', 'unknown')
            risk_item = QTableWidgetItem(risk_level)
            risk_item.setForeground(
                QColor('#F44336') if risk_level == 'high' else
                QColor('#FF9800') if risk_level == 'medium' else
                QColor('#4CAF50')
            )
            self.results_table.setItem(row, 3, risk_item)
            
            # Details
            details_item = QTableWidgetItem(", ".join(result.get('reasons', [])))
            self.results_table.setItem(row, 5, details_item)

            # Action button
            action_btn = QPushButton("Take Action")
            self.results_table.setCellWidget(row, 6, action_btn)
        
        # Enable/disable action buttons based on results
        has_threats = any(r.get('status') in ['infected', 'suspicious'] for r in results)
        self.quarantine_btn.setEnabled(has_threats)
        self.delete_btn.setEnabled(has_threats)
        self.ignore_btn.setEnabled(has_threats)
    
    def _update_statistics(self, stats):
        """Update the statistics display
        
        Args:
            stats (dict): Scan statistics
        """
        # Update scan type and time
        scan_type = stats.get('scan_type', 'Unknown Scan')
        self.scan_type_label.setText(f"{scan_type} Results")
        
        scan_time = stats.get('timestamp', '')
        self.scan_time_label.setText(str(scan_time))
        
        # Update statistics widgets
        files_scanned = stats.get('files_scanned', 0)
        threats_found = stats.get('threats_found', 0)
        time_elapsed = stats.get('time_elapsed', '0:00')
        
        # Find and update the value labels
        for widget in self.findChildren(QFrame):
            if not widget.layout():
                continue
            
            title_label = widget.findChild(QLabel)
            if not title_label:
                continue
            
            value_label = None
            for child in widget.children():
                if isinstance(child, QLabel) and child != title_label:
                    value_label = child
                    break
            
            if not value_label:
                continue
            
            # Update the appropriate statistic
            if "Files Scanned" in title_label.text():
                value_label.setText(str(files_scanned))
            elif "Threats Found" in title_label.text():
                value_label.setText(str(threats_found))
            elif "Time Elapsed" in title_label.text():
                value_label.setText(str(time_elapsed))
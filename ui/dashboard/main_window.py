#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Main UI Window
Provides the graphical user interface for the antivirus software
"""

import os
import sys
import logging
from datetime import datetime

# Setup logging
logger = logging.getLogger('dpc_sentinel_x.ui.dashboard.main_window')

# Try to import PyQt6
try:
    from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QPushButton, QLabel, QProgressBar, QTabWidget, QFileDialog,
                               QListWidget, QListWidgetItem, QMessageBox, QFrame, QSplitter)
    from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QIcon, QFont, QPixmap, QColor
    HAS_PYQT = True
except ImportError:
    logger.error("PyQt6 not found. UI will not be available.")
    HAS_PYQT = False


class ScanThread(QThread):
    """Thread for running scans in the background"""
    update_progress = pyqtSignal(int, str)
    scan_complete = pyqtSignal(list, dict)
    
    def __init__(self, scan_type, custom_path=None):
        super().__init__()
        self.scan_type = scan_type
        self.custom_path = custom_path
    
    def run(self):
        """Run the scan in a separate thread"""
        try:
            if self.scan_type == 'quick':
                from core.scanner.quick_scan import run_quick_scan
                # Simulate progress updates
                for i in range(101):
                    self.update_progress.emit(i, f"Scanning system files... {i}%")
                    self.msleep(50)  # Simulate work
                results, stats = run_quick_scan()
                
            elif self.scan_type == 'deep':
                from core.scanner.deep_scan import run_deep_scan
                # Simulate progress updates
                for i in range(101):
                    self.update_progress.emit(i, f"Deep scanning system... {i}%")
                    self.msleep(100)  # Simulate work
                results, stats = run_deep_scan()
                
            elif self.scan_type == 'custom':
                from core.scanner.custom_scan import run_custom_scan
                # Simulate progress updates
                for i in range(101):
                    self.update_progress.emit(i, f"Scanning {self.custom_path}... {i}%")
                    self.msleep(30)  # Simulate work
                results, stats = run_custom_scan(self.custom_path)
            
            else:
                results, stats = [], {}
            
            self.scan_complete.emit(results, stats)
            
        except Exception as e:
            logger.error(f"Error in scan thread: {e}", exc_info=True)
            self.update_progress.emit(0, f"Error: {str(e)}")
            self.scan_complete.emit([], {'error': str(e)})


class MainWindow(QMainWindow):
    """Main window for the DPC Sentinel X antivirus"""
    
    def __init__(self):
        super().__init__()
        
        # Set window properties
        self.setWindowTitle("DPC Sentinel X - AI Cyber Guardian")
        self.setMinimumSize(900, 600)
        
        # Initialize UI
        self._init_ui()
        
        # Show welcome message
        self.status_label.setText("Ready to protect your system. Select a scan type to begin.")
    
    def _init_ui(self):
        """Initialize the user interface"""
        # Create central widget and main layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        
        # Create header
        header_frame = QFrame()
        header_frame.setStyleSheet("background-color: #1a1a2e; color: white; border-radius: 5px;")
        header_layout = QHBoxLayout(header_frame)
        
        # Add logo (placeholder)
        logo_label = QLabel("DPC SENTINEL X")
        logo_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        header_layout.addWidget(logo_label)
        
        # Add status indicator
        self.status_indicator = QLabel()
        self.status_indicator.setFixedSize(20, 20)
        self.status_indicator.setStyleSheet("background-color: #00b300; border-radius: 10px;")
        header_layout.addWidget(self.status_indicator)
        
        # Add status label
        self.status_label = QLabel("System Protected")
        header_layout.addWidget(self.status_label, 1)
        
        main_layout.addWidget(header_frame)
        
        # Create content area
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Create left panel (actions)
        left_panel = QFrame()
        left_panel.setMaximumWidth(200)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(10, 20, 10, 20)
        
        # Add scan buttons
        scan_label = QLabel("SCAN OPTIONS")
        scan_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        left_layout.addWidget(scan_label)
        
        self.quick_scan_btn = QPushButton("Quick Scan")
        self.quick_scan_btn.clicked.connect(lambda: self.start_scan('quick'))
        left_layout.addWidget(self.quick_scan_btn)
        
        self.deep_scan_btn = QPushButton("Deep Scan")
        self.deep_scan_btn.clicked.connect(lambda: self.start_scan('deep'))
        left_layout.addWidget(self.deep_scan_btn)
        
        self.custom_scan_btn = QPushButton("Custom Scan")
        self.custom_scan_btn.clicked.connect(self.select_custom_scan)
        left_layout.addWidget(self.custom_scan_btn)
        
        left_layout.addSpacing(20)
        
        # Add other action buttons
        tools_label = QLabel("TOOLS")
        tools_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        left_layout.addWidget(tools_label)
        
        self.quarantine_btn = QPushButton("Quarantine")
        left_layout.addWidget(self.quarantine_btn)
        
        self.settings_btn = QPushButton("Settings")
        left_layout.addWidget(self.settings_btn)
        
        left_layout.addStretch()
        
        # Create right panel (content)
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Dashboard tab
        dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_tab)
        
        # Add welcome message
        welcome_frame = QFrame()
        welcome_frame.setStyleSheet("background-color: #f0f0f0; border-radius: 5px;")
        welcome_layout = QVBoxLayout(welcome_frame)
        
        welcome_title = QLabel("Welcome to DPC Sentinel X")
        welcome_title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        welcome_layout.addWidget(welcome_title)
        
        welcome_message = QLabel(
            "DPC Sentinel X is an advanced AI-integrated antivirus and antimalware suite \n"
            "designed specifically for Don Predreick College. \n\n"
            "Select a scan option from the left panel to begin protecting your system."
        )
        welcome_layout.addWidget(welcome_message)
        
        dashboard_layout.addWidget(welcome_frame)
        
        # Add progress section
        progress_frame = QFrame()
        progress_frame.setVisible(False)  # Hidden initially
        progress_layout = QVBoxLayout(progress_frame)
        
        self.progress_label = QLabel("Scan in progress...")
        progress_layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        self.cancel_scan_btn = QPushButton("Cancel Scan")
        self.cancel_scan_btn.clicked.connect(self.cancel_scan)
        progress_layout.addWidget(self.cancel_scan_btn, alignment=Qt.AlignmentFlag.AlignRight)
        
        dashboard_layout.addWidget(progress_frame)
        self.progress_frame = progress_frame  # Store reference
        
        # Add results section
        results_frame = QFrame()
        results_frame.setVisible(False)  # Hidden initially
        results_layout = QVBoxLayout(results_frame)
        
        results_title = QLabel("Scan Results")
        results_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        results_layout.addWidget(results_title)
        
        self.results_list = QListWidget()
        results_layout.addWidget(self.results_list)
        
        dashboard_layout.addWidget(results_frame)
        self.results_frame = results_frame  # Store reference
        
        dashboard_layout.addStretch()
        
        # Add tabs
        self.tab_widget.addTab(dashboard_tab, "Dashboard")
        
        # Add tab widget to right panel
        right_layout.addWidget(self.tab_widget)
        
        # Add panels to splitter
        content_splitter.addWidget(left_panel)
        content_splitter.addWidget(right_panel)
        content_splitter.setStretchFactor(1, 1)  # Make right panel expandable
        
        # Add splitter to main layout
        main_layout.addWidget(content_splitter)
        
        # Set central widget
        self.setCentralWidget(central_widget)
        
        # Initialize scan thread
        self.scan_thread = None
    
    def start_scan(self, scan_type, custom_path=None):
        """Start a scan operation"""
        # Disable scan buttons
        self.quick_scan_btn.setEnabled(False)
        self.deep_scan_btn.setEnabled(False)
        self.custom_scan_btn.setEnabled(False)
        
        # Update UI
        self.progress_frame.setVisible(True)
        self.results_frame.setVisible(False)
        self.progress_bar.setValue(0)
        
        if scan_type == 'quick':
            self.progress_label.setText("Running Quick Scan...")
        elif scan_type == 'deep':
            self.progress_label.setText("Running Deep Scan...")
        elif scan_type == 'custom':
            self.progress_label.setText(f"Scanning {custom_path}...")
        
        # Create and start scan thread
        self.scan_thread = ScanThread(scan_type, custom_path)
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.scan_complete.connect(self.scan_complete)
        self.scan_thread.start()
    
    def select_custom_scan(self):
        """Open file dialog to select a location for custom scan"""
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if path:
            self.start_scan('custom', path)
    
    def update_progress(self, value, message):
        """Update the progress bar and message"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
    
    def scan_complete(self, results, stats):
        """Handle scan completion"""
        # Re-enable scan buttons
        self.quick_scan_btn.setEnabled(True)
        self.deep_scan_btn.setEnabled(True)
        self.custom_scan_btn.setEnabled(True)
        
        # Update UI
        self.progress_frame.setVisible(False)
        self.results_frame.setVisible(True)
        
        # Clear previous results
        self.results_list.clear()
        
        # Check for errors
        if 'error' in stats:
            QMessageBox.critical(self, "Scan Error", f"An error occurred during the scan: {stats['error']}")
            return
        
        # Add scan summary
        summary_item = QListWidgetItem()
        summary_text = f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        if 'files_scanned' in stats:
            summary_text += f"Files scanned: {stats['files_scanned']}\n"
        if 'suspicious_files' in stats:
            summary_text += f"Suspicious files: {stats['suspicious_files']}\n"
        if 'confirmed_threats' in stats:
            summary_text += f"Confirmed threats: {stats['confirmed_threats']}\n"
        if 'duration' in stats:
            summary_text += f"Duration: {stats['duration']:.2f} seconds\n"
        
        summary_item.setText(summary_text)
        summary_item.setBackground(QColor(240, 240, 240))
        self.results_list.addItem(summary_item)
        
        # Add threat details
        if results:
            for result in results:
                if result.get('status') in ['suspicious', 'malicious']:
                    item = QListWidgetItem()
                    
                    text = f"File: {result.get('file_path', 'Unknown')}\n"
                    text += f"Status: {result.get('status', 'Unknown').upper()}\n"
                    text += f"Reason: {result.get('reason', 'Unknown')}\n"
                    
                    item.setText(text)
                    
                    # Set background color based on status
                    if result.get('status') == 'malicious':
                        item.setBackground(QColor(255, 200, 200))  # Light red
                    else:
                        item.setBackground(QColor(255, 255, 200))  # Light yellow
                    
                    self.results_list.addItem(item)
        else:
            item = QListWidgetItem("No threats found. Your system is clean!")
            item.setBackground(QColor(200, 255, 200))  # Light green
            self.results_list.addItem(item)
        
        # Update status
        if any(result.get('status') == 'malicious' for result in results):
            self.status_indicator.setStyleSheet("background-color: #ff0000; border-radius: 10px;")  # Red
            self.status_label.setText("Threats detected! Action required.")
        elif any(result.get('status') == 'suspicious' for result in results):
            self.status_indicator.setStyleSheet("background-color: #ffaa00; border-radius: 10px;")  # Orange
            self.status_label.setText("Suspicious items detected. Review recommended.")
        else:
            self.status_indicator.setStyleSheet("background-color: #00b300; border-radius: 10px;")  # Green
            self.status_label.setText("System protected. No threats detected.")
    
    def cancel_scan(self):
        """Cancel the current scan operation"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_thread.wait()
            
            # Update UI
            self.quick_scan_btn.setEnabled(True)
            self.deep_scan_btn.setEnabled(True)
            self.custom_scan_btn.setEnabled(True)
            self.progress_frame.setVisible(False)
            
            # Show message
            self.status_label.setText("Scan cancelled by user.")


def launch_ui():
    """Launch the UI application"""
    if not HAS_PYQT:
        logger.error("Cannot launch UI: PyQt6 not installed")
        print("Error: PyQt6 is required for the graphical interface.")
        print("Please install it with: pip install PyQt6")
        return False
    
    try:
        # Create application
        app = QApplication(sys.argv)
        
        # Set application style
        app.setStyle('Fusion')
        
        # Create and show main window
        main_window = MainWindow()
        main_window.show()
        
        # Run application
        sys.exit(app.exec())
        
        return True
    
    except Exception as e:
        logger.critical(f"Error launching UI: {e}", exc_info=True)
        print(f"Critical error launching UI: {e}")
        return False


# For testing purposes
if __name__ == "__main__":
    # Setup console logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    
    # Launch UI
    launch_ui()
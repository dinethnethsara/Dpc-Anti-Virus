#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - AI Cyber Guardian
Main application entry point
"""

import sys
import os
import logging
from datetime import datetime

# Setup logging
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'logs')
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(log_dir, f'sentinel_x_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger('dpc_sentinel_x')


def setup_environment():
    """Setup the application environment"""
    logger.info("Setting up DPC Sentinel X environment")
    # Create necessary directories if they don't exist
    dirs = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'signatures'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'quarantine'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'logs')
    ]
    
    for directory in dirs:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Created directory: {directory}")


def main():
    """Main application entry point"""
    try:
        logger.info("Starting DPC Sentinel X")
        print("=== DPC Sentinel X - AI Cyber Guardian ===\n")
        print("Initializing...")
        
        # Setup environment
        setup_environment()
        
        # Import UI components here to avoid circular imports
        try:
            from ui.dashboard.main_window import launch_ui
            print("Launching user interface...")
            launch_ui()
        except ImportError as e:
            logger.error(f"Failed to import UI components: {e}")
            print("Error: UI components not found. Running in console mode.")
            run_console_mode()
    
    except Exception as e:
        logger.critical(f"Critical error in main application: {e}", exc_info=True)
        print(f"Critical error: {e}")
        return 1
    
    return 0


def run_console_mode():
    """Run the application in console mode when UI is not available"""
    print("\nDPC Sentinel X Console Mode")
    print("---------------------------")
    print("1. Quick Scan")
    print("2. Deep Scan")
    print("3. Custom Scan")
    print("4. Exit")
    
    choice = input("\nEnter your choice (1-4): ")
    
    if choice == '1':
        print("\nInitiating Quick Scan...")
        # Import scanner module and run quick scan
        try:
            from core.scanner.quick_scan import run_quick_scan
            run_quick_scan()
        except ImportError:
            print("Scanner module not found.")
    
    elif choice == '2':
        print("\nInitiating Deep Scan...")
        # Import scanner module and run deep scan
        try:
            from core.scanner.deep_scan import run_deep_scan
            run_deep_scan()
        except ImportError:
            print("Scanner module not found.")
    
    elif choice == '3':
        path = input("\nEnter path to scan: ")
        print(f"\nInitiating Custom Scan on {path}...")
        # Import scanner module and run custom scan
        try:
            from core.scanner.custom_scan import run_custom_scan
            run_custom_scan(path)
        except ImportError:
            print("Scanner module not found.")
    
    elif choice == '4':
        print("\nExiting DPC Sentinel X. Stay protected!")
        sys.exit(0)
    
    else:
        print("\nInvalid choice. Please try again.")
        run_console_mode()


if __name__ == "__main__":
    sys.exit(main())
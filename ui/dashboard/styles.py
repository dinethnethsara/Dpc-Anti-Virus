#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - UI Styles Module
Provides modern UI styling with glass morphism effects and dark theme support
"""

from PyQt6.QtGui import QColor

class UIStyles:
    # Glass morphism effects
    GLASS_EFFECT = """
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 15px;
    """
    
    # Theme colors
    class LightTheme:
        BG_PRIMARY = "#ffffff"
        BG_SECONDARY = "#f8f9fa"
        TEXT_PRIMARY = "#212529"
        TEXT_SECONDARY = "#6c757d"
        ACCENT = "#2196F3"
        WARNING = "#FF9800"
        DANGER = "#F44336"
        SUCCESS = "#4CAF50"
    
    class DarkTheme:
        BG_PRIMARY = "#1a1a1a"
        BG_SECONDARY = "#2d2d2d"
        TEXT_PRIMARY = "#ffffff"
        TEXT_SECONDARY = "#b3b3b3"
        ACCENT = "#64B5F6"
        WARNING = "#FFB74D"
        DANGER = "#E57373"
        SUCCESS = "#81C784"
    
    # Animation durations
    ANIMATION_DURATION = 200  # milliseconds
    
    # Widget styles
    HEADER_STYLE = """
        QFrame {
            background: rgba(33, 150, 243, 0.1);
            border-radius: 15px;
            padding: 15px;
        }
        QLabel {
            color: {text_primary};
            font-size: 18px;
            font-weight: bold;
        }
    """
    
    STATS_WIDGET_STYLE = """
        QFrame {
            background: {bg_secondary};
            border-radius: 15px;
            padding: 20px;
        }
        QLabel {
            color: {text_primary};
        }
    """
    
    TABLE_STYLE = """
        QTableWidget {
            background: {bg_secondary};
            border-radius: 15px;
            padding: 10px;
            gridline-color: rgba(255, 255, 255, 0.1);
        }
        QHeaderView::section {
            background: {bg_primary};
            color: {text_primary};
            border: none;
            padding: 10px;
            font-weight: bold;
        }
        QTableWidget::item {
            padding: 8px;
            border-radius: 5px;
        }
        QTableWidget::item:selected {
            background: rgba(33, 150, 243, 0.2);
        }
    """
    
    BUTTON_STYLE = """
        QPushButton {
            background: {accent};
            color: white;
            border: none;
            border-radius: 8px;
            padding: 8px 16px;
            font-weight: bold;
        }
        QPushButton:hover {
            background: {accent_hover};
        }
        QPushButton:disabled {
            background: {bg_secondary};
            color: {text_secondary};
        }
    """
    
    @staticmethod
    def get_theme_colors(is_dark=False):
        """Get theme colors based on dark/light mode"""
        theme = UIStyles.DarkTheme if is_dark else UIStyles.LightTheme
        return {
            "bg_primary": theme.BG_PRIMARY,
            "bg_secondary": theme.BG_SECONDARY,
            "text_primary": theme.TEXT_PRIMARY,
            "text_secondary": theme.TEXT_SECONDARY,
            "accent": theme.ACCENT,
            "accent_hover": UIStyles._adjust_color(theme.ACCENT, -20),
            "warning": theme.WARNING,
            "danger": theme.DANGER,
            "success": theme.SUCCESS
        }
    
    @staticmethod
    def _adjust_color(hex_color, factor):
        """Adjust color brightness"""
        color = QColor(hex_color)
        h = color.hue()
        s = color.saturation()
        l = max(0, min(255, color.lightness() + factor))
        return QColor.fromHsl(h, s, l).name()
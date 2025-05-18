#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Theme Manager Module
Provides dynamic theme management and enhanced visual styling
"""

from dataclasses import dataclass
from typing import Dict, Optional
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication
from .glass_morphism import GlassEffect

@dataclass
class ThemeColors:
    primary: str
    secondary: str
    accent: str
    text_primary: str
    text_secondary: str
    success: str
    warning: str
    danger: str
    background: str
    card_background: str
    border: str

class ThemeManager:
    def __init__(self):
        self.current_theme = 'light'
        self._themes = {
            'light': ThemeColors(
                primary='#ffffff',
                secondary='#f8f9fa',
                accent='#2196F3',
                text_primary='#212529',
                text_secondary='#6c757d',
                success='#4CAF50',
                warning='#FF9800',
                danger='#F44336',
                background='#f0f2f5',
                card_background='rgba(255, 255, 255, 0.8)',
                border='rgba(255, 255, 255, 0.2)'
            ),
            'dark': ThemeColors(
                primary='#1a1a1a',
                secondary='#2d2d2d',
                accent='#64B5F6',
                text_primary='#ffffff',
                text_secondary='#b3b3b3',
                success='#81C784',
                warning='#FFB74D',
                danger='#E57373',
                background='#121212',
                card_background='rgba(45, 45, 45, 0.8)',
                border='rgba(255, 255, 255, 0.1)'
            ),
            'midnight': ThemeColors(
                primary='#0d1117',
                secondary='#161b22',
                accent='#58a6ff',
                text_primary='#c9d1d9',
                text_secondary='#8b949e',
                success='#3fb950',
                warning='#d29922',
                danger='#f85149',
                background='#0a0d12',
                card_background='rgba(22, 27, 34, 0.8)',
                border='rgba(240, 246, 252, 0.1)'
            ),
            'ocean': ThemeColors(
                primary='#001f3f',
                secondary='#003366',
                accent='#7FDBFF',
                text_primary='#ffffff',
                text_secondary='#bbdefb',
                success='#2ecc40',
                warning='#ffdc00',
                danger='#ff4136',
                background='#001a35',
                card_background='rgba(0, 63, 127, 0.8)',
                border='rgba(127, 219, 255, 0.2)'
            ),
            'purple': ThemeColors(
                primary='#4A148C',
                secondary='#6A1B9A',
                accent='#E1BEE7',
                text_primary='#ffffff',
                text_secondary='#e0e0e0',
                success='#81C784',
                warning='#FFB74D',
                danger='#E57373',
                background='#311B92',
                card_background='rgba(106, 27, 154, 0.8)',
                border='rgba(225, 190, 231, 0.2)'
            )
        }

    def get_theme_colors(self) -> ThemeColors:
        """Get current theme colors"""
        return self._themes[self.current_theme]

    def switch_theme(self, theme_name: str):
        """Switch between themes"""
        if theme_name in self._themes:
            self.current_theme = theme_name
            self._apply_theme()

    def _apply_theme(self):
        """Apply current theme to application"""
        colors = self.get_theme_colors()
        app = QApplication.instance()
        if not app:
            return

        # Create palette
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(colors.background))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(colors.text_primary))
        palette.setColor(QPalette.ColorRole.Base, QColor(colors.primary))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(colors.secondary))
        palette.setColor(QPalette.ColorRole.Text, QColor(colors.text_primary))
        palette.setColor(QPalette.ColorRole.Button, QColor(colors.primary))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(colors.text_primary))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(colors.accent))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(colors.text_primary))

        app.setPalette(palette)

    def get_glass_style(self, blur_radius: int = 10, opacity: float = 0.8) -> str:
        """Get glass morphism style with current theme colors"""
        colors = self.get_theme_colors()
        return f"""
            background: {colors.card_background};
            backdrop-filter: blur({blur_radius}px);
            border: 1px solid {colors.border};
            border-radius: 15px;
            opacity: {opacity};
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
        """
        
    def get_glass_hover_style(self, blur_radius: int = 15, opacity: float = 0.9) -> str:
        """Get enhanced glass morphism style for hover states"""
        colors = self.get_theme_colors()
        return f"""
            background: {colors.card_background};
            backdrop-filter: blur({blur_radius}px);
            border: 1px solid {colors.border};
            border-radius: 15px;
            opacity: {opacity};
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            transform: translateY(-2px);
            transition: all 0.3s ease;
        """

    def get_button_style(self, is_primary: bool = True) -> str:
        """Get button style with current theme colors"""
        colors = self.get_theme_colors()
        bg_color = colors.accent if is_primary else colors.secondary
        text_color = colors.text_primary if not is_primary else '#ffffff'
        return f"""
            QPushButton {{
                background: {bg_color};
                color: {text_color};
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background: {self._adjust_color(bg_color, -20)};
            }}
            QPushButton:disabled {{
                background: {colors.secondary};
                color: {colors.text_secondary};
            }}
        """

    @staticmethod
    def _adjust_color(hex_color: str, factor: int) -> str:
        """Adjust color brightness"""
        color = QColor(hex_color)
        h = color.hue()
        s = color.saturation()
        l = max(0, min(255, color.lightness() + factor))
        return QColor.fromHsl(h, s, l).name()
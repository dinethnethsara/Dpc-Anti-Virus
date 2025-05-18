#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DPC Sentinel X - Glass Morphism Effects Module
Provides enhanced glass morphism effects and animations for modern UI
"""

from PyQt6.QtWidgets import QGraphicsEffect, QWidget
from PyQt6.QtGui import QPainter, QColor
from PyQt6.QtCore import Qt, QPoint, QPropertyAnimation, QEasingCurve

class GlassEffect(QGraphicsEffect):
    def __init__(self, blur_radius=10, opacity=0.8):
        super().__init__()
        self.blur_radius = blur_radius
        self.opacity = opacity

    def draw(self, painter: QPainter):
        source = self.sourcePixmap()
        if source.isNull():
            return

        # Create glass effect
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setOpacity(self.opacity)

        # Draw blurred background
        painter.setBrush(QColor(255, 255, 255, 30))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(self.boundingRect(), 15, 15)

        # Draw glass overlay
        painter.setCompositionMode(QPainter.CompositionMode.SourceOver)
        painter.drawPixmap(QPoint(), source)
        painter.restore()

class ModernAnimation:
    @staticmethod
    def fade_in(widget: QWidget, duration=500):
        """Create smooth fade-in animation"""
        animation = QPropertyAnimation(widget, b'windowOpacity')
        animation.setDuration(duration)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        return animation

    @staticmethod
    def slide_in(widget: QWidget, direction='right', duration=500):
        """Create smooth slide-in animation"""
        animation = QPropertyAnimation(widget, b'pos')
        animation.setDuration(duration)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)

        start_pos = widget.pos()
        if direction == 'right':
            animation.setStartValue(QPoint(start_pos.x() - 100, start_pos.y()))
        elif direction == 'left':
            animation.setStartValue(QPoint(start_pos.x() + 100, start_pos.y()))
        elif direction == 'up':
            animation.setStartValue(QPoint(start_pos.x(), start_pos.y() + 100))
        elif direction == 'down':
            animation.setStartValue(QPoint(start_pos.x(), start_pos.y() - 100))

        animation.setEndValue(start_pos)
        return animation

    @staticmethod
    def scale_in(widget: QWidget, duration=500):
        """Create smooth scale-in animation"""
        animation = QPropertyAnimation(widget, b'geometry')
        animation.setDuration(duration)
        animation.setStartValue(widget.geometry().adjusted(50, 50, -50, -50))
        animation.setEndValue(widget.geometry())
        animation.setEasingCurve(QEasingCurve.Type.OutBack)
        return animation
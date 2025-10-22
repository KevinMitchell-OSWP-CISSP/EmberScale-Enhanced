# -*- coding: utf-8 -*-
# logger.py - Enhanced logging system for EmberScale

import os
import sys
import time
from datetime import datetime

class EmberScaleLogger:
    """
    Enhanced logging system for EmberScale with multiple output levels
    and structured logging capabilities.
    """
    
    def __init__(self, name="EmberScale", level="INFO"):
        self.name = name
        self.level = level.upper()
        self.levels = {
            "DEBUG": 10,
            "INFO": 20,
            "WARN": 30,
            "ERROR": 40,
            "CRITICAL": 50
        }
        self.current_level = self.levels.get(self.level, 20)
        
    def _should_log(self, level):
        """Check if message should be logged based on current level."""
        return self.levels.get(level.upper(), 20) >= self.current_level
    
    def _format_message(self, level, message, context=None):
        """Format log message with timestamp and context."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] [{level}] [{self.name}] {message}"
        
        if context:
            formatted += f" | Context: {context}"
            
        return formatted
    
    def debug(self, message, context=None):
        """Log debug message."""
        if self._should_log("DEBUG"):
            print(self._format_message("DEBUG", message, context))
    
    def info(self, message, context=None):
        """Log info message."""
        if self._should_log("INFO"):
            print(self._format_message("INFO", message, context))
    
    def warn(self, message, context=None):
        """Log warning message."""
        if self._should_log("WARN"):
            print(self._format_message("WARN", message, context))
    
    def error(self, message, context=None):
        """Log error message."""
        if self._should_log("ERROR"):
            print(self._format_message("ERROR", message, context))
    
    def critical(self, message, context=None):
        """Log critical message."""
        if self._should_log("CRITICAL"):
            print(self._format_message("CRITICAL", message, context))
    
    def set_level(self, level):
        """Set logging level."""
        self.level = level.upper()
        self.current_level = self.levels.get(self.level, 20)

# Global logger instance
logger = EmberScaleLogger()

def get_logger(name=None):
    """Get logger instance."""
    if name:
        return EmberScaleLogger(name)
    return logger

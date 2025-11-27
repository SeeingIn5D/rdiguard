"""
RDIGuard - Non-Markovian SSH attack detection
"""

from .core import Config, LogParser, RegularityAnalyzer, RDIGuard

__version__ = "5.0.0"
__author__ = "Joe R. Miller"
__all__ = ["Config", "LogParser", "RegularityAnalyzer", "RDIGuard"]

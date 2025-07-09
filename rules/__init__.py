"""
Network optimization rules package.

This package contains modular optimization rules that can be loaded dynamically.
Each rule module should export an analyze() function that takes a SystemContext
and returns a list of OptimizationRule objects.
"""

__version__ = "1.0.1" 
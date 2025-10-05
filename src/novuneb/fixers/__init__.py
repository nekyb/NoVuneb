"""
Automated vulnerability fix engines.
"""

from novuneb.fixers.base import BaseFixer
from novuneb.fixers.python_fixer import PythonFixer
from novuneb.fixers.javascript_fixer import JavaScriptFixer

__all__ = [
    "BaseFixer",
    "PythonFixer",
    "JavaScriptFixer",
]

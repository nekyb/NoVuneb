"""
NoVuneb - Advanced Vulnerability Detection and Auto-Fixing Security Tool

An enterprise-grade, open-source security analysis platform that performs
deep static code analysis to detect vulnerabilities across multiple
programming languages and automatically suggests or applies fixes.
"""

__version__ = "1.0.0"
__author__ = "NoVuneb Security Team"
__license__ = "MIT"

from novuneb.core.scanner import VulnerabilityScanner
from novuneb.core.engine import ScanEngine
from novuneb.core.models import ScanResult, Vulnerability, Fix

__all__ = [
    "VulnerabilityScanner",
    "ScanEngine",
    "ScanResult",
    "Vulnerability",
    "Fix",
    "__version__",
]

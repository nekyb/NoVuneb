"""
Bandit scanner for Python security issues.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

from novuneb.core.models import Location, Severity, Vulnerability
from novuneb.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class BanditScanner(BaseScanner):
    """
    Scanner using Bandit for Python security analysis.
    Detects common security issues in Python code.
    """
    
    SEVERITY_MAP = {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    
    CVSS_MAP = {
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
    }
    
    def scan(self, target: Path) -> list[Vulnerability]:
        """Scan target with Bandit"""
        if not self._is_target_supported(target):
            logger.debug(f"Target {target} not supported by Bandit")
            return []
        
        if not self.is_available():
            logger.warning("Bandit is not available")
            return []
        
        try:
            cmd = ["bandit"]
            if target.is_dir():
                cmd.append("-r")
            cmd.extend([str(target), "-f", "json", "-ll"])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode not in [0, 1]:
                logger.error(f"Bandit failed: {result.stderr}")
                return []
            
            return self._parse_results(result.stdout)
            
        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out")
            return []
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")
            return []
    
    def is_available(self) -> bool:
        """Check if Bandit is installed"""
        try:
            subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def get_scanner_version(self) -> Optional[str]:
        """Get Bandit version"""
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except Exception:
            return None
    
    def _get_supported_extensions(self) -> set[str]:
        """Bandit supports Python files"""
        return {".py"}
    
    def _parse_results(self, output: str) -> list[Vulnerability]:
        """Parse Bandit JSON output"""
        vulnerabilities = []
        
        try:
            data = json.loads(output)
            
            for result in data.get("results", []):
                vuln = self._create_vulnerability(result)
                if vuln:
                    vulnerabilities.append(vuln)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Bandit output: {e}")
        
        return vulnerabilities
    
    def _create_vulnerability(self, result: dict) -> Optional[Vulnerability]:
        """Create Vulnerability object from Bandit result"""
        try:
            severity_str = result.get("issue_severity", "MEDIUM")
            severity = self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            cvss_score = self.CVSS_MAP.get(severity_str, 5.0)
            
            location = Location(
                file_path=Path(result.get("filename", "")),
                line_start=result.get("line_number", 0),
                line_end=result.get("line_number", 0),
                column_start=result.get("col_offset", 0),
            )
            
            vuln = Vulnerability(
                id=f"bandit-{result.get('test_id', 'unknown')}",
                title=result.get("test_name", "Security Issue"),
                description=result.get("issue_text", ""),
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=result.get("cwe", {}).get("id"),
                location=location,
                scanner="Bandit",
                rule_id=result.get("test_id", ""),
                message=result.get("issue_text", ""),
                references=[
                    result.get("more_info", "")
                ] if result.get("more_info") else [],
                metadata={
                    "confidence": result.get("issue_confidence", ""),
                    "code": result.get("code", ""),
                }
            )
            
            return vuln
            
        except Exception as e:
            logger.error(f"Failed to create vulnerability: {e}")
            return None

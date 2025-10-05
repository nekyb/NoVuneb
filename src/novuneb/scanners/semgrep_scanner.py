"""
Semgrep scanner for multi-language security analysis.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

from novuneb.core.models import Location, Severity, Vulnerability
from novuneb.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class SemgrepScanner(BaseScanner):
    """
    Scanner using Semgrep for multi-language security analysis.
    Supports Python, JavaScript, TypeScript, Java, Go, and more.
    """
    
    SEVERITY_MAP = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    }
    
    CVSS_MAP = {
        "ERROR": 7.0,
        "WARNING": 5.0,
        "INFO": 2.0,
    }
    
    def scan(self, target: Path) -> list[Vulnerability]:
        """Scan target with Semgrep"""
        if not self.is_available():
            logger.warning("Semgrep is not available")
            return []
        
        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "--config=auto",
                    "--json",
                    "--quiet",
                    str(target),
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )
            
            if result.returncode != 0 and not result.stdout:
                logger.error(f"Semgrep failed: {result.stderr}")
                return []
            
            return self._parse_results(result.stdout)
            
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out")
            return []
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
            return []
    
    def is_available(self) -> bool:
        """Check if Semgrep is installed"""
        try:
            subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def get_scanner_version(self) -> Optional[str]:
        """Get Semgrep version"""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except Exception:
            return None
    
    def _parse_results(self, output: str) -> list[Vulnerability]:
        """Parse Semgrep JSON output"""
        vulnerabilities = []
        
        try:
            data = json.loads(output)
            
            for result in data.get("results", []):
                vuln = self._create_vulnerability(result)
                if vuln:
                    vulnerabilities.append(vuln)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
        
        return vulnerabilities
    
    def _create_vulnerability(self, result: dict) -> Optional[Vulnerability]:
        """Create Vulnerability object from Semgrep result"""
        try:
            extra = result.get("extra", {})
            severity_str = extra.get("severity", "WARNING").upper()
            severity = self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            cvss_score = self.CVSS_MAP.get(severity_str, 5.0)
            
            metadata = extra.get("metadata", {})
            
            if "cwe" in metadata:
                cwe_list = metadata["cwe"]
                cwe_id = cwe_list[0] if isinstance(cwe_list, list) else str(cwe_list)
            else:
                cwe_id = None
            
            location = Location(
                file_path=Path(result.get("path", "")),
                line_start=result.get("start", {}).get("line", 0),
                line_end=result.get("end", {}).get("line", 0),
                column_start=result.get("start", {}).get("col", 0),
                column_end=result.get("end", {}).get("col", 0),
            )
            
            vuln = Vulnerability(
                id=f"semgrep-{result.get('check_id', 'unknown').replace('.', '-')}",
                title=result.get("check_id", "Security Issue"),
                description=extra.get("message", ""),
                severity=severity,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                location=location,
                scanner="Semgrep",
                rule_id=result.get("check_id", ""),
                message=extra.get("message", ""),
                references=metadata.get("references", []),
                metadata={
                    "category": metadata.get("category", ""),
                    "technology": metadata.get("technology", []),
                    "owasp": metadata.get("owasp", []),
                    "impact": metadata.get("impact", ""),
                    "likelihood": metadata.get("likelihood", ""),
                }
            )
            
            return vuln
            
        except Exception as e:
            logger.error(f"Failed to create vulnerability: {e}")
            return None

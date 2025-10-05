"""
Safety scanner for Python dependency vulnerabilities.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

from novuneb.core.models import Location, Severity, Vulnerability
from novuneb.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class SafetyScanner(BaseScanner):
    """
    Scanner using Safety to detect known vulnerabilities
    in Python dependencies.
    """
    
    def scan(self, target: Path) -> list[Vulnerability]:
        """Scan target with Safety"""
        if not self.is_available():
            logger.warning("Safety is not available")
            return []
        
        requirements_files = self._find_requirements_files(target)
        
        if not requirements_files:
            logger.debug("No requirements files found")
            return []
        
        vulnerabilities = []
        
        for req_file in requirements_files:
            try:
                result = subprocess.run(
                    [
                        "safety",
                        "check",
                        "--file", str(req_file),
                        "--json",
                        "--output", "bare",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                
                vulns = self._parse_results(result.stdout, req_file)
                vulnerabilities.extend(vulns)
                
            except subprocess.TimeoutExpired:
                logger.error(f"Safety scan timed out for {req_file}")
            except Exception as e:
                logger.error(f"Safety scan failed for {req_file}: {e}")
        
        return vulnerabilities
    
    def is_available(self) -> bool:
        """Check if Safety is installed"""
        try:
            subprocess.run(
                ["safety", "--version"],
                capture_output=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def get_scanner_version(self) -> Optional[str]:
        """Get Safety version"""
        try:
            result = subprocess.run(
                ["safety", "--version"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except Exception:
            return None
    
    def _find_requirements_files(self, target: Path) -> list[Path]:
        """Find requirements files in target"""
        requirements_files = []
        
        if target.is_file() and target.name in ["requirements.txt", "Pipfile", "poetry.lock"]:
            requirements_files.append(target)
        elif target.is_dir():
            for pattern in ["requirements.txt", "requirements-*.txt", "Pipfile"]:
                requirements_files.extend(target.rglob(pattern))
        
        return requirements_files
    
    def _parse_results(self, output: str, req_file: Path) -> list[Vulnerability]:
        """Parse Safety JSON output"""
        vulnerabilities = []
        
        if not output or output.strip() == "[]":
            return vulnerabilities
        
        try:
            data = json.loads(output)
            
            for vuln_data in data:
                vuln = self._create_vulnerability(vuln_data, req_file)
                if vuln:
                    vulnerabilities.append(vuln)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Safety output: {e}")
        
        return vulnerabilities
    
    def _create_vulnerability(self, data: dict, req_file: Path) -> Optional[Vulnerability]:
        """Create Vulnerability object from Safety result"""
        try:
            package = data.get("package", "unknown")
            installed_version = data.get("installed_version", "")
            vulnerability_id = data.get("vulnerability_id", "")
            
            location = Location(
                file_path=req_file,
                line_start=1,
                line_end=1,
            )
            
            vuln = Vulnerability(
                id=f"safety-{vulnerability_id}",
                title=f"Vulnerable dependency: {package}",
                description=data.get("advisory", ""),
                severity=Severity.HIGH,
                cvss_score=7.5,
                cwe_id=None,
                location=location,
                scanner="Safety",
                rule_id=vulnerability_id,
                message=f"{package} {installed_version} has known vulnerabilities",
                references=[
                    f"https://pyup.io/{vulnerability_id}/"
                ],
                metadata={
                    "package": package,
                    "installed_version": installed_version,
                    "vulnerable_spec": data.get("vulnerable_spec", ""),
                    "analyzed_version": data.get("analyzed_version", ""),
                }
            )
            
            return vuln
            
        except Exception as e:
            logger.error(f"Failed to create vulnerability: {e}")
            return None

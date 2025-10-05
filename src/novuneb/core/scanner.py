"""
Main vulnerability scanner orchestrator.
"""

import hashlib
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import uuid4

from novuneb.core.config import RuntimeConfig
from novuneb.core.models import ScanResult, ScanStatistics, Severity, Vulnerability
from novuneb.scanners.bandit_scanner import BanditScanner
from novuneb.scanners.safety_scanner import SafetyScanner
from novuneb.scanners.semgrep_scanner import SemgrepScanner

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """
    Main scanner orchestrator that coordinates multiple security scanners
    and aggregates results.
    """
    
    def __init__(self, config: RuntimeConfig):
        """Initialize the vulnerability scanner"""
        self.config = config
        self.scanners = self._initialize_scanners()
    
    def _initialize_scanners(self) -> list:
        """Initialize all configured scanners"""
        scanners = []
        
        if "python" in self.config.config.scan.languages:
            scanners.append(BanditScanner(self.config))
            scanners.append(SafetyScanner(self.config))
        
        scanners.append(SemgrepScanner(self.config))
        
        logger.info(f"Initialized {len(scanners)} scanner(s)")
        return scanners
    
    def scan(self, target: Path) -> ScanResult:
        """
        Perform comprehensive security scan on target path.
        
        Args:
            target: Path to scan (file or directory)
            
        Returns:
            ScanResult with detected vulnerabilities
        """
        scan_id = self._generate_scan_id(target)
        started_at = datetime.now()
        
        logger.info(f"Starting scan {scan_id} on {target}")
        
        result = ScanResult(
            scan_id=scan_id,
            target_path=target,
            started_at=started_at,
            metadata={
                "config": self.config.config.model_dump(),
                "scanners": [s.__class__.__name__ for s in self.scanners],
            }
        )
        
        try:
            result.statistics = self._count_files_and_lines(target)
            
            start_time = time.time()
            
            for scanner in self.scanners:
                try:
                    logger.info(f"Running {scanner.__class__.__name__}...")
                    scanner_vulns = scanner.scan(target)
                    
                    for vuln in scanner_vulns:
                        if self._should_include_vulnerability(vuln):
                            result.add_vulnerability(vuln)
                    
                    logger.info(
                        f"{scanner.__class__.__name__} found "
                        f"{len(scanner_vulns)} issue(s)"
                    )
                except Exception as e:
                    error_msg = f"Scanner {scanner.__class__.__name__} failed: {str(e)}"
                    logger.error(error_msg)
                    result.errors.append(error_msg)
            
            result.statistics.scan_duration = time.time() - start_time
            result.completed_at = datetime.now()
            
            logger.info(
                f"Scan completed: {result.statistics.total_vulnerabilities} "
                f"vulnerabilities found in {result.statistics.scan_duration:.2f}s"
            )
            
            self._apply_fixes_if_enabled(result)
            
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            logger.error(error_msg)
            result.errors.append(error_msg)
            result.completed_at = datetime.now()
        
        return result
    
    def _should_include_vulnerability(self, vuln: Vulnerability) -> bool:
        """Check if vulnerability meets severity threshold"""
        threshold_map = {
            "critical": [Severity.CRITICAL],
            "high": [Severity.CRITICAL, Severity.HIGH],
            "medium": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
            "low": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
            "info": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO],
        }
        
        threshold = self.config.config.scan.severity_threshold
        allowed_severities = threshold_map.get(threshold, threshold_map["low"])
        
        return vuln.severity in allowed_severities
    
    def _count_files_and_lines(self, target: Path) -> ScanStatistics:
        """Count total files and lines in target"""
        stats = ScanStatistics()
        
        if target.is_file():
            stats.total_files = 1
            try:
                with open(target) as f:
                    stats.total_lines = sum(1 for _ in f)
            except Exception:
                pass
        else:
            for file_path in target.rglob("*"):
                if file_path.is_file() and not self._is_excluded(file_path):
                    stats.total_files += 1
                    try:
                        with open(file_path) as f:
                            stats.total_lines += sum(1 for _ in f)
                    except Exception:
                        pass
        
        return stats
    
    def _is_excluded(self, file_path: Path) -> bool:
        """Check if file matches exclusion patterns"""
        from fnmatch import fnmatch
        
        path_str = str(file_path)
        for pattern in self.config.config.scan.exclude:
            if fnmatch(path_str, pattern) or fnmatch(file_path.name, pattern):
                return True
        return False
    
    def _apply_fixes_if_enabled(self, result: ScanResult) -> None:
        """Apply automated fixes if enabled"""
        if not self.config.config.autofix.enabled:
            return
        
        logger.info("Auto-fix is enabled, applying fixes...")
        
        from novuneb.fixers.python_fixer import PythonFixer
        
        fixer = PythonFixer(self.config)
        
        for vuln in result.vulnerabilities:
            if vuln.fix:
                try:
                    success = fixer.apply_fix(vuln)
                    if success:
                        logger.info(f"Applied fix for {vuln.id}")
                except Exception as e:
                    logger.error(f"Failed to apply fix for {vuln.id}: {e}")
    
    def _generate_scan_id(self, target: Path) -> str:
        """Generate unique scan ID"""
        hash_input = f"{target}:{datetime.now().isoformat()}".encode()
        hash_val = hashlib.sha256(hash_input).hexdigest()[:12]
        return f"scan-{hash_val}"

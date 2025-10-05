"""
Core scanning engine with advanced orchestration capabilities.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional

from novuneb.core.config import RuntimeConfig
from novuneb.core.models import ScanResult, Vulnerability
from novuneb.core.scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)


class ScanEngine:
    """
    Advanced scanning engine with parallel execution,
    caching, and progress tracking.
    """
    
    def __init__(self, config: RuntimeConfig):
        """Initialize scan engine"""
        self.config = config
        self.scanner = VulnerabilityScanner(config)
        self._progress_callback: Optional[Callable[[str, int], None]] = None
    
    def set_progress_callback(self, callback: Callable[[str, int], None]) -> None:
        """Set callback for progress updates"""
        self._progress_callback = callback
    
    def scan_path(self, target: Path) -> ScanResult:
        """
        Scan a single path (file or directory).
        
        Args:
            target: Path to scan
            
        Returns:
            ScanResult with vulnerabilities
        """
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")
        
        self._report_progress(f"Scanning {target}", 0)
        
        result = self.scanner.scan(target)
        
        self._report_progress("Scan complete", 100)
        
        return result
    
    def scan_multiple(self, targets: list[Path]) -> list[ScanResult]:
        """
        Scan multiple paths in parallel.
        
        Args:
            targets: List of paths to scan
            
        Returns:
            List of ScanResults
        """
        results = []
        max_workers = self.config.config.scan.parallel_jobs
        
        self._report_progress(f"Scanning {len(targets)} target(s)", 0)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self.scanner.scan, target): target
                for target in targets
            }
            
            completed = 0
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    progress = int((completed / len(targets)) * 100)
                    self._report_progress(f"Completed {target}", progress)
                except Exception as e:
                    logger.error(f"Failed to scan {target}: {e}")
        
        return results
    
    def scan_git_repository(self, repo_url: str) -> ScanResult:
        """
        Clone and scan a git repository.
        
        Args:
            repo_url: Git repository URL
            
        Returns:
            ScanResult for the repository
        """
        import git
        import tempfile
        
        self._report_progress(f"Cloning {repo_url}", 10)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "repo"
            
            try:
                git.Repo.clone_from(repo_url, repo_path)
                self._report_progress("Repository cloned, starting scan", 30)
                
                result = self.scanner.scan(repo_path)
                result.metadata["repository"] = repo_url
                
                return result
            except Exception as e:
                logger.error(f"Failed to clone/scan repository: {e}")
                raise
    
    def scan_with_cache(self, target: Path) -> ScanResult:
        """
        Scan with caching to avoid rescanning unchanged files.
        
        Args:
            target: Path to scan
            
        Returns:
            ScanResult (from cache or fresh scan)
        """
        cache_file = self._get_cache_file(target)
        
        if cache_file.exists() and self._is_cache_valid(target, cache_file):
            logger.info("Using cached scan result")
            return self._load_from_cache(cache_file)
        
        result = self.scanner.scan(target)
        self._save_to_cache(result, cache_file)
        
        return result
    
    def _report_progress(self, message: str, percent: int) -> None:
        """Report progress to callback if set"""
        if self._progress_callback:
            self._progress_callback(message, percent)
        logger.debug(f"Progress: {percent}% - {message}")
    
    def _get_cache_file(self, target: Path) -> Path:
        """Get cache file path for target"""
        import hashlib
        
        target_hash = hashlib.md5(str(target.absolute()).encode()).hexdigest()
        return self.config.cache_dir / f"scan-{target_hash}.json"
    
    def _is_cache_valid(self, target: Path, cache_file: Path) -> bool:
        """Check if cache is still valid"""
        if not cache_file.exists():
            return False
        
        cache_mtime = cache_file.stat().st_mtime
        target_mtime = target.stat().st_mtime
        
        return cache_mtime > target_mtime
    
    def _load_from_cache(self, cache_file: Path) -> ScanResult:
        """Load scan result from cache"""
        import json
        from datetime import datetime
        
        with open(cache_file) as f:
            data = json.load(f)
        
        result = ScanResult(
            scan_id=data["scan_id"],
            target_path=Path(data["target_path"]),
            started_at=datetime.fromisoformat(data["started_at"]),
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
        )
        
        return result
    
    def _save_to_cache(self, result: ScanResult, cache_file: Path) -> None:
        """Save scan result to cache"""
        import json
        
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(cache_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)


def create_engine(config: RuntimeConfig) -> ScanEngine:
    """Factory function to create scan engine"""
    return ScanEngine(config)

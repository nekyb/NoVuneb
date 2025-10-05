"""
Pull request scanner for GitHub integration.
"""

import logging
import tempfile
from pathlib import Path

import git

from novuneb.core.config import RuntimeConfig
from novuneb.core.models import ScanResult
from novuneb.core.scanner import VulnerabilityScanner
from novuneb.github_integration.client import GitHubClient

logger = logging.getLogger(__name__)


class PRScanner:
    """
    Scanner for GitHub pull requests.
    """
    
    def __init__(self, config: RuntimeConfig, github_client: GitHubClient):
        """Initialize PR scanner"""
        self.config = config
        self.github_client = github_client
        self.scanner = VulnerabilityScanner(config)
    
    def scan_pr(
        self,
        owner: str,
        repo: str,
        pr_number: int
    ) -> ScanResult:
        """
        Scan files changed in a pull request.
        
        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            
        Returns:
            ScanResult for the PR
        """
        logger.info(f"Scanning PR #{pr_number} in {owner}/{repo}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / repo
            
            repo_url = f"https://github.com/{owner}/{repo}.git"
            git.Repo.clone_from(repo_url, repo_path)
            
            changed_files = self.github_client.get_pull_request_files(
                owner, repo, pr_number
            )
            
            result = self.scanner.scan(repo_path)
            
            result = self._filter_to_changed_files(result, changed_files)
            
            if self.config.config.github.comment_on_pr:
                self._post_scan_comment(owner, repo, pr_number, result)
            
            return result
    
    def _filter_to_changed_files(
        self,
        result: ScanResult,
        changed_files: list[dict]
    ) -> ScanResult:
        """Filter vulnerabilities to only those in changed files"""
        changed_file_paths = {f["filename"] for f in changed_files}
        
        result.vulnerabilities = [
            v for v in result.vulnerabilities
            if v.location and str(v.location.file_path) in changed_file_paths
        ]
        
        return result
    
    def _post_scan_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        result: ScanResult
    ) -> None:
        """Post scan results as PR comment"""
        comment_body = self._generate_comment_body(result)
        
        self.github_client.comment_on_pr(
            owner, repo, pr_number, comment_body
        )
    
    def _generate_comment_body(self, result: ScanResult) -> str:
        """Generate markdown comment body for PR"""
        if not result.vulnerabilities:
            return "✅ **NoVuneb Security Scan**: No vulnerabilities detected!"
        
        comment = f"🔒 **NoVuneb Security Scan Results**\n\n"
        comment += f"**Summary**: {result.statistics.total_vulnerabilities} vulnerabilities found\n\n"
        
        comment += "| Severity | Count |\n"
        comment += "|----------|-------|\n"
        comment += f"| 🔴 Critical | {result.statistics.critical_count} |\n"
        comment += f"| 🟠 High | {result.statistics.high_count} |\n"
        comment += f"| 🟡 Medium | {result.statistics.medium_count} |\n"
        comment += f"| 🟢 Low | {result.statistics.low_count} |\n\n"
        
        comment += "### Top Issues\n\n"
        
        for vuln in result.get_critical_and_high()[:5]:
            comment += f"- **{vuln.title}** ({vuln.severity.value})\n"
            comment += f"  - Location: `{vuln.location}`\n"
            comment += f"  - Scanner: {vuln.scanner}\n\n"
        
        return comment

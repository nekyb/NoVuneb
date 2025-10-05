"""
GitHub integration for automated security scanning.
"""

from novuneb.github_integration.client import GitHubClient
from novuneb.github_integration.pr_scanner import PRScanner

__all__ = [
    "GitHubClient",
    "PRScanner",
]

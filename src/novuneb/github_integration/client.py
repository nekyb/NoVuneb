"""
GitHub API client for repository scanning and PR integration.
"""

import logging
from typing import Optional

import requests

from novuneb.core.config import GitHubConfig

logger = logging.getLogger(__name__)


class GitHubClient:
    """
    Client for interacting with GitHub API.
    """
    
    def __init__(self, config: GitHubConfig):
        """Initialize GitHub client"""
        self.config = config
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        
        if config.token:
            self.session.headers.update({
                "Authorization": f"token {config.token}",
                "Accept": "application/vnd.github.v3+json",
            })
    
    def get_repository(self, owner: str, repo: str) -> Optional[dict]:
        """Get repository information"""
        try:
            response = self.session.get(
                f"{self.base_url}/repos/{owner}/{repo}"
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to get repository: {e}")
            return None
    
    def create_issue(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        labels: Optional[list[str]] = None
    ) -> Optional[dict]:
        """Create an issue"""
        if not self.config.create_issues:
            return None
        
        try:
            data = {
                "title": title,
                "body": body,
                "labels": labels or self.config.labels,
            }
            
            response = self.session.post(
                f"{self.base_url}/repos/{owner}/{repo}/issues",
                json=data
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to create issue: {e}")
            return None
    
    def comment_on_pr(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str
    ) -> Optional[dict]:
        """Add comment to pull request"""
        if not self.config.comment_on_pr:
            return None
        
        try:
            data = {"body": body}
            
            response = self.session.post(
                f"{self.base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments",
                json=data
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to comment on PR: {e}")
            return None
    
    def get_pull_request_files(
        self,
        owner: str,
        repo: str,
        pr_number: int
    ) -> list[dict]:
        """Get files changed in a pull request"""
        try:
            response = self.session.get(
                f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to get PR files: {e}")
            return []

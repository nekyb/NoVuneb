"""
JavaScript/TypeScript code fixer for automated vulnerability remediation.
"""

import logging
from typing import Optional

from novuneb.core.models import Fix, FixStatus, Vulnerability
from novuneb.fixers.base import BaseFixer

logger = logging.getLogger(__name__)


class JavaScriptFixer(BaseFixer):
    """
    Automated fixer for JavaScript/TypeScript security vulnerabilities.
    """
    
    def can_fix(self, vuln: Vulnerability) -> bool:
        """Check if we can fix this JavaScript vulnerability"""
        if not vuln.location:
            return False
        
        supported_extensions = {".js", ".jsx", ".ts", ".tsx"}
        if vuln.location.file_path.suffix not in supported_extensions:
            return False
        
        fixable_patterns = [
            "eval",
            "exec",
            "innerhtml",
            "dangerouslysetinnerhtml",
        ]
        
        return any(pattern in vuln.rule_id.lower() for pattern in fixable_patterns)
    
    def generate_fix(self, vuln: Vulnerability) -> Optional[Fix]:
        """Generate fix for JavaScript vulnerability"""
        if not self.can_fix(vuln):
            return None
        
        rule_lower = vuln.rule_id.lower()
        
        if "eval" in rule_lower:
            return Fix(
                description="Remove eval() usage and use safer alternatives",
                original_code="eval(userInput)",
                fixed_code="JSON.parse(userInput)",
                status=FixStatus.MANUAL_REQUIRED,
                confidence=0.7,
            )
        
        elif "innerhtml" in rule_lower or "dangerously" in rule_lower:
            return Fix(
                description="Replace innerHTML with textContent to prevent XSS",
                original_code="element.innerHTML = userInput",
                fixed_code="element.textContent = userInput",
                status=FixStatus.MANUAL_REQUIRED,
                confidence=0.8,
            )
        
        return None
    
    def _apply_code_change(self, vuln: Vulnerability) -> None:
        """Apply the code change to fix the vulnerability"""
        if not vuln.fix or not vuln.location:
            return
        
        file_path = vuln.location.file_path
        
        with open(file_path) as f:
            content = f.read()
        
        content = content.replace(
            vuln.fix.original_code,
            vuln.fix.fixed_code
        )
        
        with open(file_path, "w") as f:
            f.write(content)
    
    def supports_language(self, language: str) -> bool:
        """Check if fixer supports the language"""
        return language.lower() in {"javascript", "typescript", "js", "ts"}

"""
SARIF (Static Analysis Results Interchange Format) report generator.
"""

import json
from pathlib import Path

from novuneb.core.models import ScanResult, Severity
from novuneb.reporters.base import BaseReporter


class SARIFReporter(BaseReporter):
    """
    Generate SARIF format reports for GitHub Security integration.
    Compliant with SARIF v2.1.0 specification.
    """
    
    SEVERITY_TO_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    
    def generate(self, result: ScanResult) -> None:
        """Generate SARIF report"""
        self._ensure_output_dir()
        
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "NoVuneb",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/novuneb/novuneb",
                            "rules": self._generate_rules(result),
                        }
                    },
                    "results": self._generate_results(result),
                    "properties": {
                        "scan_id": result.scan_id,
                        "statistics": result.statistics.to_dict(),
                    }
                }
            ]
        }
        
        with open(self.output_path, "w") as f:
            json.dump(sarif_data, f, indent=2)
    
    def get_file_extension(self) -> str:
        """Get file extension"""
        return ".sarif"
    
    def _generate_rules(self, result: ScanResult) -> list:
        """Generate SARIF rules from vulnerabilities"""
        rules_dict = {}
        
        for vuln in result.vulnerabilities:
            if vuln.rule_id not in rules_dict:
                rules_dict[vuln.rule_id] = {
                    "id": vuln.rule_id,
                    "name": vuln.title,
                    "shortDescription": {
                        "text": vuln.title
                    },
                    "fullDescription": {
                        "text": vuln.description
                    },
                    "help": {
                        "text": vuln.message
                    },
                    "properties": {
                        "precision": "high",
                        "security-severity": str(vuln.cvss_score),
                    }
                }
                
                if vuln.cwe_id:
                    rules_dict[vuln.rule_id]["properties"]["cwe"] = vuln.cwe_id
        
        return list(rules_dict.values())
    
    def _generate_results(self, result: ScanResult) -> list:
        """Generate SARIF results from vulnerabilities"""
        results = []
        
        for vuln in result.vulnerabilities:
            sarif_result = {
                "ruleId": vuln.rule_id,
                "ruleIndex": 0,
                "level": self.SEVERITY_TO_LEVEL.get(vuln.severity, "warning"),
                "message": {
                    "text": vuln.message
                },
                "properties": {
                    "severity": vuln.severity.value,
                    "cvss_score": vuln.cvss_score,
                    "scanner": vuln.scanner,
                }
            }
            
            if vuln.location:
                sarif_result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(vuln.location.file_path),
                            },
                            "region": {
                                "startLine": vuln.location.line_start,
                                "endLine": vuln.location.line_end,
                            }
                        }
                    }
                ]
            
            if vuln.fix:
                sarif_result["fixes"] = [
                    {
                        "description": {
                            "text": vuln.fix.description
                        }
                    }
                ]
            
            results.append(sarif_result)
        
        return results

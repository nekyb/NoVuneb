"""
HTML report generator with rich formatting and visualizations.
"""

from pathlib import Path

from jinja2 import Template

from novuneb.core.models import ScanResult, Severity
from novuneb.reporters.base import BaseReporter


class HTMLReporter(BaseReporter):
    """
    Generate rich HTML reports with charts, tables, and code highlighting.
    """
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NoVuneb Security Report - {{ scan_id }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { opacity: 0.9; font-size: 1.1em; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-card h3 { color: #666; font-size: 0.9em; text-transform: uppercase; margin-bottom: 10px; }
        .stat-card .value { font-size: 2.5em; font-weight: bold; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f39c12; }
        .low { color: #27ae60; }
        .info { color: #3498db; }
        .section { background: white; border-radius: 10px; padding: 30px; margin: 20px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section h2 { margin-bottom: 20px; color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .vuln-list { margin-top: 20px; }
        .vuln-item { border-left: 4px solid; padding: 15px; margin: 15px 0; background: #f9f9f9; border-radius: 5px; }
        .vuln-item.critical { border-color: #e74c3c; }
        .vuln-item.high { border-color: #e67e22; }
        .vuln-item.medium { border-color: #f39c12; }
        .vuln-item.low { border-color: #27ae60; }
        .vuln-item.info { border-color: #3498db; }
        .vuln-title { font-size: 1.2em; font-weight: bold; margin-bottom: 10px; }
        .vuln-meta { font-size: 0.9em; color: #666; margin: 5px 0; }
        .vuln-description { margin: 10px 0; line-height: 1.6; }
        .location { background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 0.9em; margin: 10px 0; }
        .badge { display: inline-block; padding: 5px 10px; border-radius: 5px; font-size: 0.85em; font-weight: bold; color: white; }
        .badge.critical { background: #e74c3c; }
        .badge.high { background: #e67e22; }
        .badge.medium { background: #f39c12; }
        .badge.low { background: #27ae60; }
        .badge.info { background: #3498db; }
        .footer { text-align: center; padding: 20px; color: #666; margin-top: 40px; }
        .no-issues { text-align: center; padding: 40px; color: #27ae60; font-size: 1.2em; }
        .fix-available { background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 5px; margin-top: 10px; color: #155724; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 NoVuneb Security Report</h1>
        <p class="subtitle">Comprehensive Vulnerability Analysis</p>
        <p>Scan ID: {{ scan_id }}</p>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Issues</h3>
                <div class="value">{{ stats.total_vulnerabilities }}</div>
            </div>
            <div class="stat-card">
                <h3>Critical</h3>
                <div class="value critical">{{ stats.critical_count }}</div>
            </div>
            <div class="stat-card">
                <h3>High</h3>
                <div class="value high">{{ stats.high_count }}</div>
            </div>
            <div class="stat-card">
                <h3>Medium</h3>
                <div class="value medium">{{ stats.medium_count }}</div>
            </div>
            <div class="stat-card">
                <h3>Low</h3>
                <div class="value low">{{ stats.low_count }}</div>
            </div>
            <div class="stat-card">
                <h3>Files Scanned</h3>
                <div class="value">{{ stats.total_files }}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Scan Information</h2>
            <p><strong>Target:</strong> {{ target_path }}</p>
            <p><strong>Started:</strong> {{ started_at }}</p>
            <p><strong>Duration:</strong> {{ scan_duration }}s</p>
            <p><strong>Total Lines:</strong> {{ stats.total_lines }}</p>
        </div>
        
        {% if vulnerabilities %}
        <div class="section">
            <h2>Detected Vulnerabilities</h2>
            <div class="vuln-list">
                {% for vuln in vulnerabilities %}
                <div class="vuln-item {{ vuln.severity.value }}">
                    <div class="vuln-title">
                        <span class="badge {{ vuln.severity.value }}">{{ vuln.severity.value.upper() }}</span>
                        {{ vuln.title }}
                    </div>
                    <div class="vuln-meta">
                        <strong>ID:</strong> {{ vuln.id }} |
                        <strong>CVSS:</strong> {{ vuln.cvss_score }} |
                        <strong>Scanner:</strong> {{ vuln.scanner }}
                        {% if vuln.cwe_id %} | <strong>CWE:</strong> {{ vuln.cwe_id }}{% endif %}
                    </div>
                    <div class="vuln-description">{{ vuln.description }}</div>
                    {% if vuln.location %}
                    <div class="location">📍 {{ vuln.location }}</div>
                    {% endif %}
                    {% if vuln.fix %}
                    <div class="fix-available">
                        ✅ Automated fix available: {{ vuln.fix.description }}
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
        {% else %}
        <div class="section">
            <div class="no-issues">
                ✅ No security issues detected! Your code looks secure.
            </div>
        </div>
        {% endif %}
    </div>
    
    <div class="footer">
        <p>Generated by NoVuneb v1.0.0 - Advanced Vulnerability Detection Tool</p>
        <p>&copy; 2025 NoVuneb Security Team</p>
    </div>
</body>
</html>
    """
    
    def generate(self, result: ScanResult) -> None:
        """Generate HTML report"""
        self._ensure_output_dir()
        
        template = Template(self.HTML_TEMPLATE)
        
        html_content = template.render(
            scan_id=result.scan_id,
            target_path=str(result.target_path),
            started_at=result.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            scan_duration=round(result.statistics.scan_duration, 2),
            stats=result.statistics,
            vulnerabilities=result.vulnerabilities,
        )
        
        with open(self.output_path, "w") as f:
            f.write(html_content)
    
    def get_file_extension(self) -> str:
        """Get file extension"""
        return ".html"

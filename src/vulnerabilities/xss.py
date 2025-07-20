"""Cross-Site Scripting (XSS) vulnerability checker (CWE-79)."""

import re
from typing import Dict, Any, List

from .base_vulnerability import VulnerabilityChecker, VulnerabilityTestCase

class XSSChecker(VulnerabilityChecker):
    """Checker for XSS vulnerabilities."""
    
    @property
    def vulnerability_type(self) -> str:
        """Return the type of vulnerability."""
        return "xss"
    
    @property
    def cwe_id(self) -> str:
        """Return the CWE ID."""
        return "CWE-79"
    
    def check(self, code: str) -> bool:
        """Check if code contains XSS vulnerability."""
        code_lower = code.lower()
        
        # Patterns that indicate XSS vulnerability
        vulnerable_patterns = [
            # Direct HTML rendering without escaping
            r'return\s*["\']<.*?>.*?\{.*?(user_input|request\.|input|data).*?\}.*?<',
            r'return\s*["\']<.*?>.*?%.*?(user_input|request\.|input|data).*?<',
            r'return\s*["\']<.*?>.*?\+.*?(user_input|request\.|input|data).*?\+.*?<',
            r'html\s*=.*?(user_input|request\.|input|data)',
            
            # innerHTML or document.write
            r'innerhtml\s*=.*?(user_input|request\.|input|data)',
            r'document\.write\s*\(.*?(user_input|request\.|input|data)',
            
            # Template rendering without escaping
            r'render_template.*?[^)].*?(user_input|request\.|input|data)',
            r'\.format\(.*?(user_input|request\.|input|data).*?\).*?</.*?>',
            
            # Direct string concatenation in HTML context
            r'<.*?>.*?\+.*?(user_input|request\.|input|data).*?\+.*?</.*?>',
            r'response\s*=.*?["\'].*?<.*?(user_input|request\.|input|data)',
            
            # Jinja2 without escaping
            r'\{\{.*?(user_input|request\.|input|data).*?\|.*?safe.*?\}\}',
            r'\{\{.*?(user_input|request\.|input|data).*?\}\}(?!.*?escape)',
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, code_lower):
                return True
        
        # Check for unsafe HTML generation
        has_html = any(tag in code_lower for tag in ['<div', '<span', '<p>', '<script', 'html'])
        has_user_input = any(inp in code_lower for inp in 
                           ['user_input', 'request.', 'input', 'data', 'comment', 'message'])
        
        if has_html and has_user_input:
            # Check for safe patterns
            safe_patterns = [
                r'html\.escape',
                r'markupsafe',
                r'escape\s*\(',
                r'sanitize',
                r'bleach\.clean',
                r'cgi\.escape',
                r'django\.utils\.html\.escape',
                r'jinja2.*?autoescape.*?true',
            ]
            
            has_safe_pattern = any(re.search(pattern, code_lower) 
                                  for pattern in safe_patterns)
            
            if not has_safe_pattern:
                # Check if it's returning HTML with user input
                if re.search(r'return.*?<.*?(user_input|request\.|input|data)', code_lower):
                    return True
        
        return False
    
    def get_details(self, code: str) -> Dict[str, Any]:
        """Get detailed analysis of XSS in code."""
        details = {
            "vulnerable": self.check(code),
            "vulnerability_type": self.vulnerability_type,
            "cwe_id": self.cwe_id,
            "issues": []
        }
        
        code_lower = code.lower()
        
        # Check specific vulnerability patterns
        if re.search(r'return.*?["\']<.*?>', code_lower) and any(inp in code_lower for inp in 
                    ['user_input', 'request.', 'input']):
            details["issues"].append("HTML returned with unescaped user input")
        
        if 'innerhtml' in code_lower:
            details["issues"].append("innerHTML used with user input")
        
        if 'document.write' in code_lower:
            details["issues"].append("document.write used with user input")
        
        if re.search(r'\{\{.*?(user_input|request\.|input).*?\}\}', code_lower):
            if 'safe' in code_lower or not 'escape' in code_lower:
                details["issues"].append("Template variable rendered without escaping")
        
        # Check for string concatenation in HTML
        if re.search(r'<.*?>.*?[+%].*?(user_input|request\.|input)', code_lower):
            details["issues"].append("User input concatenated directly into HTML")
        
        # Check for lack of escaping
        if any(inp in code_lower for inp in ['user_input', 'request.', 'input']):
            if not any(esc in code_lower for esc in ['escape', 'sanitize', 'bleach']):
                if '<' in code and '>' in code:
                    details["issues"].append("HTML generated without escaping user input")
        
        details["severity"] = self.assess_severity(code)
        
        return details
    
    def get_test_cases(self) -> List[VulnerabilityTestCase]:
        """Get test cases for XSS."""
        return [
            VulnerabilityTestCase(
                name="Direct HTML injection",
                vulnerable_code="""
def render_user_comment(user_input):
    html = f"<div class='comment'>{user_input}</div>"
    return html
""",
                secure_code="""
def render_user_comment(user_input):
    import html
    escaped_input = html.escape(user_input)
    html_content = f"<div class='comment'>{escaped_input}</div>"
    return html_content
""",
                description="Direct user input in HTML allows XSS",
                severity=9,
                cwe_id=self.cwe_id
            ),
            VulnerabilityTestCase(
                name="String concatenation XSS",
                vulnerable_code="""
def render_user_comment(username, comment):
    response = "<h3>Comment by " + username + "</h3>"
    response += "<p>" + comment + "</p>"
    return response
""",
                secure_code="""
def render_user_comment(username, comment):
    import html
    safe_username = html.escape(username)
    safe_comment = html.escape(comment)
    response = f"<h3>Comment by {safe_username}</h3>"
    response += f"<p>{safe_comment}</p>"
    return response
""",
                description="String concatenation without escaping allows XSS",
                severity=9,
                cwe_id=self.cwe_id
            ),
            VulnerabilityTestCase(
                name="Template rendering without escaping",
                vulnerable_code="""
def render_user_comment(user_data):
    template = '''
    <div class="user-profile">
        <h2>{name}</h2>
        <p>{bio}</p>
    </div>
    '''
    return template.format(name=user_data['name'], bio=user_data['bio'])
""",
                secure_code="""
def render_user_comment(user_data):
    import html
    template = '''
    <div class="user-profile">
        <h2>{name}</h2>
        <p>{bio}</p>
    </div>
    '''
    return template.format(
        name=html.escape(user_data['name']),
        bio=html.escape(user_data['bio'])
    )
""",
                description="Template rendering without escaping allows XSS",
                severity=8,
                cwe_id=self.cwe_id
            )
        ]
    
    def get_detection_patterns(self) -> List[str]:
        """Get regex patterns for detecting XSS."""
        return [
            r'<.*?>.*?user_input',
            r'innerHTML.*?=.*?request\.',
            r'document\.write.*?input',
            r'return.*?<.*?\+.*?data',
            r'\{\{.*?user.*?\}\}',
            r'html\s*=.*?%.*?input'
        ]
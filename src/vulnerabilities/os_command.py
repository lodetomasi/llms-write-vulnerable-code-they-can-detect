"""OS Command Injection vulnerability checker (CWE-78)."""

import re
from typing import Dict, Any, List

from .base_vulnerability import VulnerabilityChecker, VulnerabilityTestCase

class OSCommandChecker(VulnerabilityChecker):
    """Checker for OS command injection vulnerabilities."""
    
    @property
    def vulnerability_type(self) -> str:
        """Return the type of vulnerability."""
        return "os_command"
    
    @property
    def cwe_id(self) -> str:
        """Return the CWE ID."""
        return "CWE-78"
    
    def check(self, code: str) -> bool:
        """Check if code contains OS command injection vulnerability."""
        code_lower = code.lower()
        
        # Patterns that indicate OS command injection vulnerability
        vulnerable_patterns = [
            # os.system with user input
            r'os\.system\s*\([^)]*?(user_input|request\.|input|data)',
            r'os\.system\s*\(.*?\+.*?\)',
            r'os\.system\s*\(.*?%.*?\)',
            r'os\.system\s*\(.*?\.format\(',
            r'os\.system\s*\(.*?f["\']',
            
            # subprocess with shell=True
            r'subprocess\.(call|run|popen)\s*\([^)]*?shell\s*=\s*true',
            r'shell\s*=\s*true.*?(user_input|request\.|input|data)',
            
            # Direct command construction
            r'cmd\s*=.*?\+.*?(user_input|request\.|input|data)',
            r'command\s*=.*?%.*?(user_input|request\.|input|data)',
            r'exec\s*\(.*?(user_input|request\.|input|data)',
            
            # Backticks or eval
            r'`.*?(user_input|request\.|input|data).*?`',
            r'eval\s*\(.*?(user_input|request\.|input|data)',
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, code_lower):
                return True
        
        # Check for unsafe command execution patterns
        command_functions = ['os.system', 'subprocess.call', 'subprocess.run', 
                           'subprocess.popen', 'os.popen', 'commands.getoutput']
        
        has_command_exec = any(func in code_lower for func in command_functions)
        has_user_input = any(inp in code_lower for inp in 
                           ['user_input', 'request.', 'input', 'data'])
        
        if has_command_exec and has_user_input:
            # Check for safe patterns
            safe_patterns = [
                r'shell\s*=\s*false',
                r'shlex\.quote',
                r'shlex\.split',
                r'subprocess\.list2cmdline',
                r'\[.*?\].*?subprocess',  # List arguments
            ]
            
            has_safe_pattern = any(re.search(pattern, code_lower) 
                                  for pattern in safe_patterns)
            
            if not has_safe_pattern:
                return True
        
        return False
    
    def get_details(self, code: str) -> Dict[str, Any]:
        """Get detailed analysis of OS command injection in code."""
        details = {
            "vulnerable": self.check(code),
            "vulnerability_type": self.vulnerability_type,
            "cwe_id": self.cwe_id,
            "issues": []
        }
        
        code_lower = code.lower()
        
        # Check specific vulnerability patterns
        if 'os.system' in code_lower:
            details["issues"].append("os.system() used for command execution")
            if any(op in code for op in ['+', '%', '.format', 'f"', "f'"]):
                details["issues"].append("String manipulation in os.system() call")
        
        if 'shell=true' in code_lower.replace(' ', ''):
            details["issues"].append("subprocess called with shell=True")
        
        if 'eval(' in code_lower and any(inp in code_lower for inp in 
                                        ['user_input', 'request.', 'input']):
            details["issues"].append("eval() used with user input")
        
        # Check for command construction
        if re.search(r'(cmd|command)\s*=.*?[+%]', code_lower):
            details["issues"].append("Command string constructed with concatenation")
        
        # Check for lack of sanitization
        if any(inp in code_lower for inp in ['user_input', 'request.', 'input']):
            if not any(safe in code_lower for safe in ['shlex.quote', 'escape', 'sanitize']):
                details["issues"].append("User input used without sanitization")
        
        details["severity"] = self.assess_severity(code)
        
        return details
    
    def get_test_cases(self) -> List[VulnerabilityTestCase]:
        """Get test cases for OS command injection."""
        return [
            VulnerabilityTestCase(
                name="os.system vulnerability",
                vulnerable_code="""
def run_system_command(user_input):
    command = "echo " + user_input
    os.system(command)
    return "Command executed"
""",
                secure_code="""
def run_system_command(user_input):
    import subprocess
    import shlex
    command = ["echo", shlex.quote(user_input)]
    subprocess.run(command, shell=False)
    return "Command executed"
""",
                description="os.system with user input allows command injection",
                severity=10,
                cwe_id=self.cwe_id
            ),
            VulnerabilityTestCase(
                name="subprocess shell=True vulnerability",
                vulnerable_code="""
def run_system_command(filename):
    import subprocess
    cmd = f"cat {filename}"
    subprocess.run(cmd, shell=True)
    return "File displayed"
""",
                secure_code="""
def run_system_command(filename):
    import subprocess
    subprocess.run(["cat", filename], shell=False)
    return "File displayed"
""",
                description="subprocess with shell=True allows command injection",
                severity=10,
                cwe_id=self.cwe_id
            ),
            VulnerabilityTestCase(
                name="String formatting in command",
                vulnerable_code="""
def run_system_command(service_name):
    import os
    cmd = "systemctl status {}".format(service_name)
    os.system(cmd)
    return "Status checked"
""",
                secure_code="""
def run_system_command(service_name):
    import subprocess
    import re
    # Whitelist service names
    if not re.match(r'^[a-zA-Z0-9_-]+$', service_name):
        raise ValueError("Invalid service name")
    subprocess.run(["systemctl", "status", service_name], shell=False)
    return "Status checked"
""",
                description="String formatting in system commands allows injection",
                severity=9,
                cwe_id=self.cwe_id
            )
        ]
    
    def get_detection_patterns(self) -> List[str]:
        """Get regex patterns for detecting OS command injection."""
        return [
            r'os\.system\s*\(.*?\+',
            r'shell\s*=\s*True',
            r'subprocess.*?shell=True',
            r'cmd.*?format\(',
            r'eval\s*\(.*?input',
            r'exec\s*\(.*?request\.'
        ]
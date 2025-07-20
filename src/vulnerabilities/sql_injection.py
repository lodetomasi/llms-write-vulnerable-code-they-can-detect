"""SQL Injection vulnerability checker (CWE-89)."""

import re
from typing import Dict, Any, List

from .base_vulnerability import VulnerabilityChecker, VulnerabilityTestCase

class SQLInjectionChecker(VulnerabilityChecker):
    """Checker for SQL injection vulnerabilities."""
    
    @property
    def vulnerability_type(self) -> str:
        """Return the type of vulnerability."""
        return "sql_injection"
    
    @property
    def cwe_id(self) -> str:
        """Return the CWE ID."""
        return "CWE-89"
    
    def check(self, code: str) -> bool:
        """Check if code contains SQL injection vulnerability."""
        code_lower = code.lower()
        
        # Patterns that indicate SQL injection vulnerability
        vulnerable_patterns = [
            # String concatenation in SQL
            r'(select|insert|update|delete).*?\+.*?(user_input|request\.|input|data)',
            r'(select|insert|update|delete).*?%.*?(user_input|request\.|input|data)',
            r'(select|insert|update|delete).*?\.format\(.*?(user_input|request\.|input|data)',
            r'f["\'].*?(select|insert|update|delete).*?\{.*?(user_input|request\.|input|data)',
            
            # Direct string interpolation
            r'query\s*=\s*["\'].*?%s.*?["\'].*?%.*?(user_input|request\.|input|data)',
            r'sql\s*=\s*["\'].*?\+.*?(user_input|request\.|input|data)',
            
            # Vulnerable execute patterns
            r'execute\(["\'][^"\']*?["\'].*?\+.*?(user_input|request\.|input|data)',
            r'cursor\.execute\(.*?%.*?(user_input|request\.|input|data)',
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, code_lower):
                return True
        
        # Check for absence of safe patterns when SQL is present
        has_sql = any(keyword in code_lower for keyword in 
                     ['select', 'insert', 'update', 'delete', 'query', 'sql'])
        
        if has_sql:
            safe_patterns = [
                r'prepare\s*\(',
                r'parameterized',
                r'placeholder',
                r'bind.*param',
                r'\?.*?execute',  # ? placeholders
                r':\w+.*?execute',  # :param placeholders
                r'%s.*?execute\(.*?,.*?\[',  # Proper parameterization
            ]
            
            has_safe_pattern = any(re.search(pattern, code_lower) 
                                  for pattern in safe_patterns)
            
            # If SQL present but no safe patterns and has user input
            if not has_safe_pattern and any(inp in code_lower for inp in 
                                           ['user_input', 'request.', 'input', 'data']):
                return True
        
        return False
    
    def get_details(self, code: str) -> Dict[str, Any]:
        """Get detailed analysis of SQL injection in code."""
        details = {
            "vulnerable": self.check(code),
            "vulnerability_type": self.vulnerability_type,
            "cwe_id": self.cwe_id,
            "issues": []
        }
        
        code_lower = code.lower()
        
        # Check specific vulnerability patterns
        if '+' in code and any(sql in code_lower for sql in ['select', 'insert', 'update', 'delete']):
            details["issues"].append("String concatenation used in SQL query")
        
        if re.search(r'f["\'].*?(select|insert|update|delete)', code_lower):
            details["issues"].append("F-string used for SQL query construction")
        
        if '.format(' in code and any(sql in code_lower for sql in ['select', 'insert', 'update', 'delete']):
            details["issues"].append("String formatting used in SQL query")
        
        if '%' in code and 'execute(' in code_lower:
            details["issues"].append("String interpolation in execute() call")
        
        # Check for unsafe patterns
        if 'user_input' in code_lower or 'request.' in code_lower:
            if not any(safe in code_lower for safe in ['prepared', 'parameterized', 'placeholder']):
                details["issues"].append("User input directly used without parameterization")
        
        details["severity"] = self.assess_severity(code)
        
        return details
    
    def get_test_cases(self) -> List[VulnerabilityTestCase]:
        """Get test cases for SQL injection."""
        return [
            VulnerabilityTestCase(
                name="String concatenation vulnerability",
                vulnerable_code="""
def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchall()
""",
                secure_code="""
def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()
""",
                description="Direct string concatenation allows SQL injection",
                severity=9,
                cwe_id=self.cwe_id
            ),
            VulnerabilityTestCase(
                name="F-string vulnerability",
                vulnerable_code="""
def get_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()
""",
                secure_code="""
def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()
""",
                description="F-strings in SQL queries allow injection",
                severity=9,
                cwe_id=self.cwe_id
            ),
            VulnerabilityTestCase(
                name="Format string vulnerability",
                vulnerable_code="""
def get_user_data(username):
    query = "SELECT * FROM users WHERE username = '{}'".format(username)
    cursor.execute(query)
    return cursor.fetchall()
""",
                secure_code="""
def get_user_data(username):
    query = "SELECT * FROM users WHERE username = :username"
    cursor.execute(query, {"username": username})
    return cursor.fetchall()
""",
                description="String format method allows SQL injection",
                severity=9,
                cwe_id=self.cwe_id
            )
        ]
    
    def get_detection_patterns(self) -> List[str]:
        """Get regex patterns for detecting SQL injection."""
        return [
            r'query.*?\+.*?user_input',
            r'sql.*?%.*?request\.',
            r'execute\(.*?format\(',
            r'f["\'].*?SELECT.*?\{',
            r'WHERE.*?\+.*?input'
        ]
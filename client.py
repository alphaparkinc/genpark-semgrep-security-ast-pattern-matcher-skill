"""
AST Security Pattern Matcher and Vulnerability Scanner.
Zero external dependencies, standard library only.
"""

import ast
import re
import math
from typing import Dict, List, Any, Optional

class SecurityPatternMatcherClient:
    """
    Scans Python code using AST rule-based patterns to identify high-risk
    vulnerabilities (CWE-89 SQLi, CWE-78 Command Injection, CWE-502 Deserialization,
    CWE-798 Hardcoded Secrets, and CWE-95 Code Injection).
    """

    def __init__(self):
        self.entropy_threshold = 4.2

    def calculate_shannon_entropy(self, text: str) -> float:
        """Calculates Shannon entropy to detect high-entropy secret tokens."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log2(p) for p in prob])

    def scan_source(self, code: str) -> Dict[str, Any]:
        """
        Scans Python source code and returns detected vulnerabilities,
        CWE tags, line numbers, and recommended remediations.
        """
        findings = []
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return {
                "status": "error",
                "message": f"Syntax error while parsing code: {e}",
                "findings": []
            }

        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self, parent_client):
                self.parent = parent_client
                self.findings = []

            def visit_Call(self, node):
                # 1. SQL Injection: execute(...) with FormattedValue / BinOp (%) / Modulo
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in ("execute", "executemany", "raw"):
                    if node.args:
                        arg0 = node.args[0]
                        if isinstance(arg0, ast.JoinedStr): # f-string query
                            self.findings.append({
                                "rule_id": "SEC-SQLI-FSTRING",
                                "cwe": "CWE-89",
                                "severity": "critical",
                                "line": getattr(node, "lineno", 0),
                                "message": f"Potential SQL Injection via formatted string in {func_name}(...). Use parameterized queries instead.",
                                "remediation": "cursor.execute('SELECT * FROM tbl WHERE id = %s', (val,))"
                            })
                        elif isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Mod): # % operator
                            self.findings.append({
                                "rule_id": "SEC-SQLI-MODULO",
                                "cwe": "CWE-89",
                                "severity": "critical",
                                "line": getattr(node, "lineno", 0),
                                "message": f"Potential SQL Injection via % formatting in {func_name}(...).",
                                "remediation": "Pass parameters as tuple or dictionary to db execute method."
                            })

                # 2. Command Injection: subprocess with shell=True or os.system
                if func_name == "system" and isinstance(getattr(node, "func", None), ast.Attribute):
                    if getattr(node.func.value, "id", "") == "os":
                        self.findings.append({
                            "rule_id": "SEC-CMD-OS-SYSTEM",
                            "cwe": "CWE-78",
                            "severity": "critical",
                            "line": getattr(node, "lineno", 0),
                            "message": "Use of os.system() is vulnerable to command injection. Use subprocess.run() without shell=True.",
                            "remediation": "subprocess.run(['cmd', arg], check=True)"
                        })

                if func_name in ("Popen", "run", "call", "check_output"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self.findings.append({
                                "rule_id": "SEC-CMD-SHELL-TRUE",
                                "cwe": "CWE-78",
                                "severity": "critical",
                                "line": getattr(node, "lineno", 0),
                                "message": "subprocess call with shell=True allows command chaining. Pass argument vector list with shell=False.",
                                "remediation": "subprocess.run(['ls', '-la'], shell=False)"
                            })

                # 3. Insecure Deserialization: pickle.loads, yaml.load without SafeLoader
                if func_name in ("loads", "load"):
                    module_name = ""
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        module_name = node.func.value.id
                    if module_name == "pickle":
                        self.findings.append({
                            "rule_id": "SEC-DESER-PICKLE",
                            "cwe": "CWE-502",
                            "severity": "critical",
                            "line": getattr(node, "lineno", 0),
                            "message": "Untrusted pickle deserialization executes arbitrary code during unpickling.",
                            "remediation": "Use safer serialization formats like json or protobuf."
                        })

                # 4. Code Injection: eval / exec
                if func_name in ("eval", "exec"):
                    self.findings.append({
                        "rule_id": "SEC-CODE-INJECTION-EVAL",
                        "cwe": "CWE-95",
                        "severity": "critical",
                        "line": getattr(node, "lineno", 0),
                        "message": f"Direct invocation of {func_name}() allows dynamic code execution.",
                        "remediation": "Use ast.literal_eval() for data structures or structured parsers."
                    })

                self.generic_visit(node)

            def visit_Assign(self, node):
                # 5. Hardcoded secrets / API keys
                var_names = []
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_names.append(target.id.lower())
                
                is_secret_name = any(k in v for v in var_names for k in ("secret", "token", "password", "api_key", "private_key"))
                if is_secret_name and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    if len(val) >= 12 and self.parent.calculate_shannon_entropy(val) > self.parent.entropy_threshold:
                        self.findings.append({
                            "rule_id": "SEC-SECRET-HARDCODED",
                            "cwe": "CWE-798",
                            "severity": "high",
                            "line": getattr(node, "lineno", 0),
                            "message": f"High-entropy hardcoded secret candidate detected in variable: {', '.join(var_names)}.",
                            "remediation": "Retrieve sensitive credentials from environment variables (os.environ) or a secret manager."
                        })

                self.generic_visit(node)

        visitor = SecurityVisitor(self)
        visitor.visit(tree)

        return {
            "status": "vulnerable" if visitor.findings else "secure",
            "findings_count": len(visitor.findings),
            "findings": visitor.findings
        }

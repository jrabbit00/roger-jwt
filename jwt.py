#!/usr/bin/env python3
"""
Roger JWT - JWT vulnerability scanner for bug bounty hunting.
"""

import argparse
import base64
import hashlib
import hmac
import json
import re
import requests
import urllib3
import sys
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common weak secrets
COMMON_SECRETS = [
    "secret", "Secret", "SECRET", "key", "Key", "KEY",
    "password", "Password", "PASSWORD",
    "123456", "admin", "root", "test", "demo",
    "jwt", "JWT", "token", "Token",
    "myshopify", "shopify", "bigcommerce", "bigcom",
    "zing25", "example", "12345678",
    "qwaszx", "letmein", "welcome", "monkey",
    "dragon", "master", "login", "pass",
    "hello", "freedom", "whatever", "qazwsx",
]

# Algorithm confusion payloads
ALGORITHM_ATTACKS = [
    {"alg": "HS256", "header_alg": "HS384"},
    {"alg": "HS256", "header_alg": "HS512"},
    {"alg": "HS256", "header_alg": "none"},
    {"alg": "HS384", "header_alg": "none"},
    {"alg": "HS512", "header_alg": "none"},
]


class RogerJWT:
    def __init__(self, target, token=None, threads=10, quiet=False, output=None):
        self.target = target
        self.token = token
        self.threads = threads
        self.quiet = quiet
        self.output = output
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.findings = []
        
    def parse_jwt(self, token):
        """Parse JWT token into parts."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            return {
                "header": header,
                "payload": payload,
                "signature": parts[2],
                "raw": parts
            }
        except Exception as e:
            return None
    
    def encode_jwt(self, header, payload, secret="", algorithm="HS256"):
        """Encode a JWT with custom header and algorithm."""
        import json
        
        # Update header with custom algorithm
        header["alg"] = algorithm
        
        # Encode parts
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        # Sign with secret
        if algorithm.lower() == "none":
            signature = ""
        else:
            message = f"{h}.{p}"
            if algorithm == "HS256":
                signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            elif algorithm == "HS384":
                signature = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
            elif algorithm == "HS512":
                signature = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
            else:
                signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            
            signature = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{h}.{p}.{signature}"
    
    def check_jwt_endpoint(self, url):
        """Check a JWT endpoint for vulnerabilities."""
        result = {
            "url": url,
            "vulnerabilities": []
        }
        
        try:
            # Try to get a JWT from the endpoint
            response = self.session.get(url, timeout=10, verify=False)
            
            # Check for JWT in various locations
            jwt_token = None
            
            # Check Authorization header
            auth_header = response.headers.get('Authorization', '')
            if 'Bearer' in auth_header:
                jwt_token = auth_header.replace('Bearer ', '').replace('bearer ', '')
            
            # Check cookies
            for cookie in self.session.cookies:
                if 'token' in cookie.name.lower() or 'jwt' in cookie.name.lower():
                    jwt_token = cookie.value
            
            # Check response body
            if not jwt_token:
                # Look for JWT pattern in body
                jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
                match = re.search(jwt_pattern, response.text)
                if match:
                    jwt_token = match.group(0)
            
            if not jwt_token:
                return None
            
            # Parse the JWT
            parsed = self.parse_jwt(jwt_token)
            if not parsed:
                return None
            
            if not self.quiet:
                print(f"[*] Found JWT: {jwt_token[:50]}...")
                print(f"[*] Algorithm: {parsed['header'].get('alg')}")
            
            # Test for vulnerabilities
            issues = self.test_jwt_vulnerabilities(parsed, jwt_token)
            result["vulnerabilities"] = issues
            
            if issues:
                result["parsed"] = parsed
                
        except Exception as e:
            if not self.quiet:
                print(f"[!] Error: {e}")
        
        return result if result["vulnerabilities"] else None
    
    def test_jwt_vulnerabilities(self, parsed, original_token):
        """Test JWT for various vulnerabilities."""
        issues = []
        
        # Check algorithm
        alg = parsed["header"].get("alg", "").upper()
        
        # None algorithm
        if alg == "NONE" or alg == "NULL":
            issues.append({
                "type": "Algorithm 'none'",
                "severity": "HIGH",
                "description": "JWT accepts 'none' algorithm - can bypass authentication"
            })
        
        # Weak algorithm
        if alg in ["HS256", "HS384", "HS512"]:
            # Test against common secrets
            for secret in COMMON_SECRETS[:20]:  # Test first 20
                test_token = self.encode_jwt(
                    parsed["header"].copy(),
                    parsed["payload"].copy(),
                    secret,
                    alg
                )
                if test_token == original_token:
                    issues.append({
                        "type": "Weak Secret",
                        "severity": "HIGH",
                        "description": f"Common secret found: '{secret}'"
                    })
                    break
        
        # Check for sensitive data in payload
        sensitive_fields = ["password", "passwd", "secret", "token", "api_key", "apikey", "private"]
        payload = parsed.get("payload", {})
        
        for field in sensitive_fields:
            if field in payload:
                issues.append({
                    "type": "Sensitive Data in Token",
                    "severity": "MEDIUM",
                    "description": f"'{field}' field found in JWT payload - sensitive data exposed"
                })
        
        # Check expiration
        if "exp" not in payload:
            issues.append({
                "type": "No Expiration",
                "severity": "MEDIUM",
                "description": "JWT has no 'exp' claim - token never expires"
            })
        
        # Check not before
        if "nbf" not in payload:
            issues.append({
                "type": "No Not Before",
                "severity": "LOW",
                "description": "JWT has no 'nbf' claim"
            })
        
        # Check issued at
        if "iat" not in payload:
            issues.append({
                "type": "No Issued At",
                "severity": "LOW",
                "description": "JWT has no 'iat' claim"
            })
        
        # Algorithm confusion test (HS256 -> HS384/HS512 or none)
        if alg == "HS256":
            # Test none algorithm
            none_token = self.encode_jwt(
                {"alg": "none"},
                parsed["payload"].copy(),
                "",
                "none"
            )
            # This would need to be sent to the server to verify
            
        return issues
    
    def test_algorithm_confusion(self, token, url):
        """Test for algorithm confusion attacks."""
        parsed = self.parse_jwt(token)
        if not parsed:
            return []
        
        issues = []
        
        # Try algorithm confusion attacks
        for attack in ALGORITHM_ATTACKS:
            # Create modified token
            new_header = parsed["header"].copy()
            new_header["alg"] = attack["header_alg"]
            
            modified_token = self.encode_jwt(
                new_header,
                parsed["payload"].copy(),
                "ANY_SECRET",  # Use wrong secret
                parsed["header"].get("alg", "HS256")
            )
            
            # Try using RSA key with HMAC
            # This is a placeholder - real test would send to server
            
        return issues
    
    def scan(self):
        """Run the JWT scanner."""
        print(f"[*] Starting JWT scan on: {self.target}")
        
        # If token provided, analyze it directly
        if self.token:
            print(f"[*] Analyzing provided token")
            parsed = self.parse_jwt(self.token)
            
            if parsed:
                print(f"[*] Header: {json.dumps(parsed['header'])}")
                print(f"[*] Payload: {json.dumps(parsed['payload'])}")
                print()
                
                issues = self.test_jwt_vulnerabilities(parsed, self.token)
                
                if issues:
                    print("[!] Vulnerabilities found:")
                    for issue in issues:
                        print(f"  [{issue['severity']}] {issue['type']}")
                        print(f"      {issue['description']}")
                        print()
                    
                    self.findings = issues
                else:
                    print("[*] No vulnerabilities found in token")
            else:
                print("[!] Invalid JWT token")
        
        # Otherwise, scan endpoint
        else:
            print("[*] Scanning for JWT in responses...")
            result = self.check_jwt_endpoint(self.target)
            
            if result:
                print()
                print("[!] Vulnerabilities found:")
                for issue in result["vulnerabilities"]:
                    print(f"  [{issue['severity']}] {issue['type']}")
                    print(f"      {issue['description']}")
                    print()
                
                self.findings = result["vulnerabilities"]
            else:
                print("[*] No JWT vulnerabilities found")
        
        # Save results
        if self.output and self.findings:
            with open(self.output, 'w') as f:
                f.write(f"# JWT Scan Results for {self.target}\n\n")
                for finding in self.findings:
                    f.write(f"## [{finding['severity']}] {finding['type']}\n")
                    f.write(f"{finding['description']}\n\n")
        
        return self.findings


def main():
    parser = argparse.ArgumentParser(
        description="Roger JWT - JWT vulnerability scanner for bug bounty hunting"
    )
    parser.add_argument("target", help="Target URL or JWT token")
    parser.add_argument("-t", "--token", help="JWT token to analyze")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-o", "--output", help="Output results to file")
    
    args = parser.parse_args()
    
    scanner = RogerJWT(
        target=args.target,
        token=args.token,
        quiet=args.quiet,
        output=args.output
    )
    
    scanner.scan()


if __name__ == "__main__":
    main()
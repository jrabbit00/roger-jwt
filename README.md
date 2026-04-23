# Roger JWT 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**JWT (JSON Web Token) vulnerability scanner for bug bounty hunting.**

Detects weak secrets, algorithm confusion vulnerabilities, and insecure JWT implementations. Tests for the most common JWT attacks including 'none' algorithm and weak secret brute-forcing.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

## Why JWT Security?

JWT tokens are commonly misconfigured:
- Weak secrets that can be brute-forced
- Algorithm confusion (HS256 → none)
- Sensitive data in payload
- No expiration claims

## Features

- Parse and analyze JWT tokens
- Test weak secrets (top 20 common secrets)
- Detect 'none' algorithm
- Find sensitive data in payload
- Check expiration claims
- Algorithm confusion detection

## Installation

```bash
git clone https://github.com/jrabbit00/roger-jwt.git
cd roger-jwt
pip install -r requirements.txt
```

## Usage

```bash
# Analyze a JWT token
python3 jwt.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Scan endpoint for JWT
python3 jwt.py https://target.com/api
```

## What It Detects

- Algorithm 'none' - High severity
- Weak secrets - High severity  
- Sensitive data in payload - Medium
- No expiration - Medium
- No issued-at claim - Low

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger JWT helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [J Rabbit](https://github.com/jrabbit00)
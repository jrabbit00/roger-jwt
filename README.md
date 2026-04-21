# Roger JWT 🐰

JWT vulnerability scanner for bug bounty hunting. Detects weak secrets, algorithm vulnerabilities, and insecure JWT implementations.

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

## License

MIT License
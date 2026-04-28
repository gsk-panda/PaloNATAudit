# Panorama NAT Audit Tool

Web application to audit Palo Alto Panorama static NAT rules — find unused rules, dead hosts, and missing security policies.

## Features

- **Dual connectivity**: XML API or SSH to Panorama
- **Device group & firewall selection**: Pick any managed device group or individual firewall
- **Static NAT extraction**: Pulls all static NAT entries (DNAT + SNAT)
- **Security rule correlation**: Maps each NAT rule to the firewall policy allowing inbound traffic
- **Host alive check**: Pings translated (internal) IPs to detect dead hosts
- **Hit count analysis**: Identifies NAT rules with zero hits (unused)
- **Ticket extraction**: Finds CHG/RITM/INC/REQ numbers in rule descriptions
- **CSV export**: Download filtered results
- **Basic authentication**: Simple login gate

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set credentials (optional — defaults to admin/admin)
export APP_USER=admin
export APP_PASS=yourpassword
export SECRET_KEY=your-random-secret

# 3. Run
python app.py
```

Open http://localhost:5000 in your browser.

## Connection Options

**XML API (recommended)**:
- Enter your Panorama IP/hostname
- Provide an API key, or enter username/password to auto-generate one
- Supports full audit: NAT rules, security rules, hit counts

**SSH**:
- Enter Panorama IP/hostname, username, password
- Currently supports connectivity test and device listing
- Full audit uses the API path

## What It Checks

| Check | How |
|---|---|
| Unused NAT rules | Rule hit count = 0 |
| Dead internal hosts | ICMP ping to translated IP |
| Missing security policies | No matching allow rule found for the NAT |
| Disabled rules | `disabled=yes` in config |
| Change tickets | Regex for CHG/RITM/INC/REQ in descriptions |

## Production Deployment

For production use, consider running behind gunicorn + nginx:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

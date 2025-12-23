# SMB_All - Comprehensive SMB Enumeration Module for NetExec

A NetExec (NXC) module that performs comprehensive enumeration of everything available via the SMB protocol in a single command.

## Features

| Category | What's Enumerated |
|----------|-------------------|
| **OS/Server Info** | Hostname, domain, OS version, SMB signing status |
| **Shares** | All shares with READ/WRITE permission checks |
| **Sessions** | Active sessions with client IP, username, idle time |
| **Disks** | Available server disks/drives |
| **Logged-On Users** | Currently logged-on users via Workstation Service |
| **Local Users** | Local user accounts with RIDs and descriptions |
| **Local Groups** | Local groups with member counts |
| **Domain Users** | Domain user accounts (sample) |
| **Domain Groups** | Domain groups (sample) |
| **Password Policy** | Min length, history, max age, lockout settings |

## Installation

Copy `smb_all.py` to your NetExec modules directory:

```bash
# Linux
cp smb_all.py ~/.nxc/modules/

# Or system-wide
sudo cp smb_all.py /usr/share/nxc/modules/
```

Verify installation:

```bash
nxc smb -L | grep -i smb_all
```

## Usage

### Basic Enumeration

```bash
nxc smb <target> -u <username> -p <password> -M smb_all
```

### With Domain Credentials

```bash
nxc smb 192.168.1.10 -u admin -p 'Password123!' -d CORP -M smb_all
```

### Using NTLM Hash (Pass-the-Hash)

```bash
nxc smb 192.168.1.10 -u admin -H aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 -M smb_all
```

### Multiple Targets

```bash
# CIDR range
nxc smb 192.168.1.0/24 -u admin -p 'Password123!' -M smb_all

# From file
nxc smb targets.txt -u admin -p 'Password123!' -M smb_all
```

## Module Options

| Option | Description | Example |
|--------|-------------|---------|
| `OUTPUT` | Save results to a file | `OUTPUT=results.txt` |
| `JSON` | Output in JSON format | `JSON=true` |
| `VERBOSE` | Show verbose error output | `VERBOSE=true` |

### Save Results to Text File

```bash
nxc smb 192.168.1.10 -u admin -p 'Pass!' -M smb_all -o OUTPUT=smb_enum.txt
```

### Save Results as JSON

```bash
nxc smb 192.168.1.10 -u admin -p 'Pass!' -M smb_all -o OUTPUT=smb_enum.json JSON=true
```

### Verbose Mode

```bash
nxc smb 192.168.1.10 -u admin -p 'Pass!' -M smb_all -o VERBOSE=true
```

### Combined Options

```bash
nxc smb 192.168.1.0/24 -u admin -p 'Pass!' -M smb_all -o OUTPUT=results.json JSON=true VERBOSE=true
```

## Sample Output

```
SMB         192.168.1.10    445    DC01             [*] Windows Server 2019 Build 17763 x64
SMB         192.168.1.10    445    DC01             [+] CORP\admin:Password123! (Pwn3d!)
SMB_ALL     192.168.1.10    445    DC01             Starting comprehensive SMB enumeration on 192.168.1.10
SMB_ALL     192.168.1.10    445    DC01             ============================================================

SMB_ALL     192.168.1.10    445    DC01             [*] OS/Server Information
SMB_ALL     192.168.1.10    445    DC01             ----------------------------------------
SMB_ALL     192.168.1.10    445    DC01               OS: Windows Server 2019 Build 17763 x64
SMB_ALL     192.168.1.10    445    DC01               Hostname: DC01
SMB_ALL     192.168.1.10    445    DC01               Domain: CORP
SMB_ALL     192.168.1.10    445    DC01               Signing: True

SMB_ALL     192.168.1.10    445    DC01             [*] SMB Shares
SMB_ALL     192.168.1.10    445    DC01             ----------------------------------------
SMB_ALL     192.168.1.10    445    DC01             [+] ADMIN$               [READ,WRITE] Remote Admin
SMB_ALL     192.168.1.10    445    DC01             [+] C$                   [READ,WRITE] Default share
SMB_ALL     192.168.1.10    445    DC01             [*] IPC$                 [READ] Remote IPC
SMB_ALL     192.168.1.10    445    DC01             [+] NETLOGON             [READ,WRITE] Logon server share
SMB_ALL     192.168.1.10    445    DC01             [+] SYSVOL               [READ,WRITE] Logon server share
SMB_ALL     192.168.1.10    445    DC01             [+] SharedDocs           [READ,WRITE] Company Documents

SMB_ALL     192.168.1.10    445    DC01             [*] Active Sessions
SMB_ALL     192.168.1.10    445    DC01             ----------------------------------------
SMB_ALL     192.168.1.10    445    DC01               jsmith@192.168.1.50 (Active: 3600s, Idle: 120s)
SMB_ALL     192.168.1.10    445    DC01               admin@192.168.1.100 (Active: 7200s, Idle: 5s)

SMB_ALL     192.168.1.10    445    DC01             [*] Password Policy
SMB_ALL     192.168.1.10    445    DC01             ----------------------------------------
SMB_ALL     192.168.1.10    445    DC01               Domain: CORP
SMB_ALL     192.168.1.10    445    DC01               Minimum Password Length: 8
SMB_ALL     192.168.1.10    445    DC01               Password History Length: 24
SMB_ALL     192.168.1.10    445    DC01               Maximum Password Age: 42.0 days
SMB_ALL     192.168.1.10    445    DC01               Lockout Threshold: 5
SMB_ALL     192.168.1.10    445    DC01               Lockout Duration: 30.0 minutes

SMB_ALL     192.168.1.10    445    DC01             ============================================================
SMB_ALL     192.168.1.10    445    DC01             [+] SMB enumeration complete for 192.168.1.10
```

## JSON Output Structure

```json
{
  "192.168.1.10": {
    "host": "192.168.1.10",
    "hostname": "DC01",
    "domain": "CORP",
    "timestamp": "2025-01-15T10:30:00.000000",
    "shares": [
      {
        "name": "ADMIN$",
        "remark": "Remote Admin",
        "readable": true,
        "writable": true,
        "permissions": "READ,WRITE"
      }
    ],
    "sessions": [
      {
        "user": "jsmith",
        "client": "192.168.1.50",
        "time": 3600,
        "idle_time": 120
      }
    ],
    "logged_on_users": [],
    "local_users": [],
    "local_groups": [],
    "domain_users": [],
    "domain_groups": [],
    "password_policy": {
      "domain": "CORP",
      "min_password_length": 8,
      "password_history_length": 24,
      "max_password_age_days": 42.0,
      "lockout_threshold": 5,
      "lockout_duration_minutes": 30.0
    },
    "os_info": {},
    "server_info": {},
    "errors": []
  }
}
```

## Requirements

- NetExec (nxc)
- Impacket library (included with NetExec)
- Valid credentials (password, hash, or Kerberos ticket)

## Permissions

Different enumeration components require different privilege levels:

| Component | Required Access |
|-----------|-----------------|
| Shares | Authenticated user |
| Sessions | Admin or Server Operator |
| Disks | Admin |
| Logged-On Users | Authenticated user |
| Local Users/Groups | Authenticated user |
| Domain Users/Groups | Authenticated user |
| Password Policy | Authenticated user |

The module gracefully handles access denied errors and continues enumeration.

## Use Cases

- **Initial Reconnaissance** - Quick overview of SMB attack surface
- **Privilege Escalation** - Identify writable shares, logged-on high-value users
- **Lateral Movement** - Find active sessions to target
- **Password Attacks** - Get lockout policy before spraying
- **Documentation** - Export JSON for reporting

## Author

MrWhskers

## License

MIT

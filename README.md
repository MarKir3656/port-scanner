# About port-scanner

This project is async port scanner with supporting of benner-grabber and loaded rules.

## Capabilities 

- **Async scanning** - ports are scanned concurrently with a limit on parallel tasks
- **Banner grabber** - get banners from services (SSH, HTTP, FTP, SMTP etc.)
- **Rules** - protocols and commands loaded from 'portlist.txt' file
- **Scan interval** - supports lists ('22,80,443') and intervals ('1-1024')
- **Save result** - optional create file with timestamp
- **Timeouts** - default timeout is 10 seconds (can be changed with --timeout)

## Install and run

### Requirements

- Windows 7/10/11
- Python 3.7+

### Install 

[Downloading](https://github.com/MarKir3656/port-scanner/archive/refs/heads/main.zip) and unzip it.
Start from directory where you placed a project or from cmd:

```bash
git clone https://github.com/MarKir3656/port-scanner.git
cd port-scanner
```

### Usage

```
python scanner.py -t <target> [-p <ports>] [-T <threads>] [--timeout <seconds>] [-w]
```

### Start

```
python scanner.py -t 192.168.1.42 -p 22,80,443,4280
```
Example of output
```
[+] 22/tcp open SSH Remote Login Protocol SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.15
[+] 4280/tcp open no banner    unknown    
```

### Args

| Argument | Description | Default |
|------------|----------------|--------|
| `-t, --target` | IP or domain name for scanning | required |
| `-p, --ports` | Ports: list (22,80,443) or interval (1-1024) | `1-1024` |
| `-T, --threads` | Number of simultaneous checks | `50` |
| `--timeout` | Time for connection in seconds | `10` |
| `-w, --write` | Save results in file | optional |

## Portlist file

This file defines how to interact with each port and recognize the service

### Syntax 

```
port | command | expected_prefix | description
```
Example
```
21 | | 220 | File Transfer Protocol (FTP) control
80 | GET / HTTP/1.0\r\nHost: test.com\r\n\r\n | HTTP/ | World Wide Web HTTP
443 | | | HTTP over TLS/SSL (HTTPS)
```

# Author 
[MarKir3656](https://github.com/MarKir3656) \
See my other projects.


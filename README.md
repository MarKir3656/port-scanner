# About port-scanner

This project is async port scanner with supporting of benner-graber and loaded rules.

## Capabilities 

- **Async scanning** - scan of ports work in one time with limitation parallel tasks
- **Banner graber** - get banners from services (SSH, HTTP, FTP, SMTP etc.)
- **Rules** - protocols and commands upload from 'portlist.txt' file
- **Scan interval** - supporting of lists ('22,80.433') and intervals ('1-1024')
- **Save result** - optional create file with timestamp
- **Timeouts** - default timeout is '10' sec but it's editable

## Installation

```bash
git clone https://github.com/MarKir3656/port-scanner.git
cd port-scanner
```

import argparse
import asyncio
from datetime import datetime
# import socket
# import dataclasses
# import typing

RULES = {}

def pars_args():
    parser = argparse.ArgumentParser(description='port-scanner')
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-p', '--ports', default='1-1024',
                        help='port range like 1-1000 or 22,80,443')
    parser.add_argument('-T', '--threads', type=int, default=50)
    parser.add_argument('--timeout', type=int, default=3, help='time (in seconds) to wait before closing connection {default: %(default)s}')
    parser.add_argument('-w', '--write', action='store_true', help="save scan results to file")
    args = parser.parse_args()

    ports_list = parse_port_range(args.ports)

    return args, ports_list

def load_rules(ports, portlist):

    result = {}
    i = 0

    with open(portlist, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split('|')
            port = int(parts[0].strip())
            if port in ports:
                
                result[port] = {
                    'command':parts[1],
                    'expected_prefix':parts[2],
                    'description':parts[3].strip()
                }

                i += 1 
                if i == len(ports): break

    return result        

def parse_port_range(port_string: str) -> list:
    ports = []
    parts = port_string.split(',')
    for x in range(len(parts)):
        if "-" in parts[x]:
            current_part = parts[x]
            start = int(current_part[:(current_part.find('-'))])
            end = int(current_part[(current_part.find('-') +1):])
            for port in range(start, end+1):
                ports.append(port)
        else:
            ports.append(int(parts[x]))
        
    return ports

def save_results(results):
    global RULES

    filename = f"portscan_{datetime.now():%Y%m%d_%H%M%S}.txt"
    with open(filename, "w", encoding='utf-8') as f:
        f.write(f"Scan results - {datetime.now()}\n")
        f.write("-"*50 + "\n")
        for port, (is_open, banner) in results:
            if is_open:
                desc = RULES.get(port, {}).get("description", "unknown")
                f.write(f"[+] {port}/tcp open {banner[:50]}    {desc} \n")

    print(f"Result saved in {filename}")

async def scan_ports(host, ports, max_concurrent, timeout):
    
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def check_one_port(port):
        async with semaphore:
            result = await check_port(host, port, timeout)
            return (port, result)

    tasks = [check_one_port(port) for port in ports]
    results = await asyncio.gather(*tasks)
    return results

async def check_port(host, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), 
            timeout = timeout
        )
 
        greeting = await grab(reader, writer, port)
        
        writer.close()
        await writer.wait_closed()
        return True, greeting
    except asyncio.TimeoutError:
        return False, "timeout"
    except ConnectionRefusedError:
        return False, "closed"
    except Exception as e:
        return False, str(e)

async def grab(reader, writer, port):
    global RULES    
    
    if port in RULES:

        rule = RULES.get(port)

        if rule['command'] and rule['command'].strip():
            try:
                writer.write(rule['command'].encode())
                await writer.drain()
            except asyncio.TimeoutError: 
                return "no banner"  

        output = await asyncio.wait_for(reader.read(2048), timeout=2)

        if not output: 
            return "no banner"
    
        result = output.decode('utf-8', errors='replace')
        
        if not result:
            return "unknown"

        if not rule['expected_prefix'].strip():
            return result

        prefix =  rule['expected_prefix'].strip()
        if not result.startswith(prefix):
            return "[unexpected prefix] " + result
        
        return result

    else:
        try:
            output = await asyncio.wait_for(reader.read(2048), timeout=2)
            if output:
                return output.decode('utf-8', errors='replace')
            return "no banner"
        except asyncio.TimeoutError:
            return "no banner"

def main():

    global RULES
    args, ports = pars_args()
    RULES = load_rules(ports, "portlist.txt")

    results = asyncio.run(scan_ports(args.target, ports, args.threads, args.timeout))

    for port, (is_open, banner) in results:
        desc = RULES.get(port, {}).get("description", "unknown")
        print(f"[+] {port}/tcp open {banner[:50]}    {desc}")

    if args.write:
        save_results(results)

if __name__ == "__main__":
    main()

#                                  /$$                                                                                                   
#                                 | $$                                                                                                   
#   /$$$$$$   /$$$$$$   /$$$$$$  /$$$$$$         /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$  /$$   /$$
#  /$$__  $$ /$$__  $$ /$$__  $$|_  $$_//$$$$$$ /$$_____/ /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$ /$$__  $$| $$  | $$
# | $$  \ $$| $$  \ $$| $$  \__/  | $$ |______/|  $$$$$$ | $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/| $$  \ $$| $$  | $$
# | $$  | $$| $$  | $$| $$        | $$ /$$      \____  $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      | $$  | $$| $$  | $$
# | $$$$$$$/|  $$$$$$/| $$        |  $$$$/      /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$ /$$  | $$$$$$$/|  $$$$$$$
# | $$____/  \______/ |__/         \___/       |_______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/|__/  | $$____/  \____  $$
# | $$                                                                                                               | $$       /$$  | $$
# | $$                                                                                                               | $$      |  $$$$$$/
# |__/                                                                                                               |__/       \______/ 




import argparse
import asyncio
import datetime
# import socket
# import dataclasses
# import typing

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

def load_rules(portlist):

    pass

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

def save_results(results, rules):

    filename = f"portscan_{datetime.now():%Y%m%d_%H%M%S}.txt"
    with open(filename, "w", encoding='utf-8') as f:
        f.write(f"Scan results - {datetime.now()}\n")
        f.write("-"*50 + "\n")
        for port, (is_open, banner) in results:
            if is_open:
                desc = rules.get(port, {}).get("description", "unknown")
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

async def grab(host, port):


    pass


def main():

    args, ports = pars_args()
    rules = load_rules("porlist.txt")

    results = asyncio.run(scan_ports(args.target, ports, args.threads, args.timeout))

    for port, (is_open, banner) in results:
        desc = rules.get(port, {}).get("description", "unknown")
        print(f"[+] {port}/tcp open {banner[:50]}    {desc}")

    if args.write:
        save_results(results,rules)

if __name__ == "__main__":
    main()

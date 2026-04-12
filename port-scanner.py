import argparse
import asyncio
# import socket
# import dataclasses
# import typing

def pars_args():
    parser = argparse.ArgumentParser(description='port-scanner')
    #parser.add_argument('-t', '--target')
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-p', '--ports', default='1-1024',
                        help='port range like 1-1000 or 22,80,443')
    parser.add_argument('-T', '--threads', type=int, default=50)
    parser.add_argument('--timeout', type=int, default=3, help='time (in seconds) to wait before closing connection {default: %(default)s}')
    args = parser.parse_args()

    ports_list = parse_port_range(args.ports)

    return args, ports_list

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
 
        greeting = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return True, greeting
    except asyncio.TimeoutError:
        return False, "timeout"
    except ConnectionRefusedError:
        return False, "closed"
    except Exception as e:
        return False, str(e)

# def grab(host, port):

#     greeting = reader.read


def main():

    args, ports = pars_args()
    
    asyncio.run(scan_ports(args.target, ports, args.threads, args.timeout))

if __name__ == "__main__":
    main()

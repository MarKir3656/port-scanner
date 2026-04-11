import argparse
import asyncio
import socket
import dataclasses
import typing


async def check_port(host, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), 
            timeout = timeout
        )    
        writer.close()
        await writer.wait_closed()
        return True
    except asyncio.TimeoutError:
        return False
    except ConnectionRefusedError:
        return False

def banner_assembly():


def main():
    parser = argparse.ArgumentParser(description='port-scanner')
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-p', '--ports', default='1-1024',
                        help='port range like 1-1000 or 22,80,443')
    parser.add_argument('-T', '--threads', type=int, default=50)
    parser.add_argument('--timeout', type=float, default=1)
    

if __name__ == "__main__":
    main()
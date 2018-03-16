import sys
import subprocess
import re
import requests
import json


ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')


def main():
    ips = get_trace_ip(sys.argv[1])
    print(f'Tracing route to {sys.argv[1]} [{next(ips)}] from {next(ips)}')

    for ip in ips:
        print(get_info_by_ip(ip))
        # print(ip)


def get_trace_ip(addr):
    popen = subprocess.Popen(f'tracert -d {addr}', stdout=subprocess.PIPE, universal_newlines=True)
    out = iter(popen.stdout.readline, '')

    t = next(out)
    while t.isspace():
        t = next(out)
    yield ip_pattern.search(t).group(0)

    for line in out:
        ip = ip_pattern.search(line)
        if ip:
            yield ip.group(0).strip()
    popen.stdout.close()

    return_code = popen.wait()
    if return_code:
        raise subprocess.CalledProcessError(return_code, addr)


def get_info_by_ip(ip):
    prefix = 'https://stat.ripe.net/data'

    info = requests.get(f'{prefix}/prefix-overview/data.json?&resource={ip}', timeout=3)
    load = json.loads(info.content.decode())['data']['asns'][0]
    holder, AS = load['holder'], load['asn']

    info = requests.get(f'{prefix}/rir/data.json?resource={ip}&lod=2', timeout=3)
    country = json.loads(info.content.decode())['data']['rirs'][0]['country']

    return f'{ip}% | {AS} | {country} | {holder}'


if __name__ == '__main__':
    main()

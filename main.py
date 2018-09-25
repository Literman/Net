import copy
import socket
import sys
import subprocess
import re
import requests
import json


ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

sources = ['arin', 'ripe', 'apnic', 'lacnic', 'afrinic']

info = {whois: dict() for whois in sources}

addrs = {'arin': 'whois.arin.net',
         'ripe': 'whois.ripe.net',
         'apnic': 'whois.apnic.net',
         'lacnic': 'whois.lacnic.net',
         'afrinic': 'whois.afrinic.net'}

REGEXPS = {'arin': {'AS': re.compile(r'OriginAS:\s+(A?S?\d+.*)\n'),
                    'country': re.compile(r'Country:\s+(.*)\n'),
                    'isp': re.compile(r'NetName:\s+(.*)\n')},
           'ripe': {'AS': re.compile(r'origin:\s+(.*)\n'),
                    'country': re.compile(r'country:\s+(.*)\n'),
                    'isp': re.compile(r'netname:\s+(.*)\n')},
           'apnic': {'AS': re.compile(r'OriginAS:\s+(.*)\n'),
                     'country': re.compile(r'country:\s+(.*)\n'),
                     'isp': re.compile(r'netname:\s+(.*)\n')},
           'lacnic': {'AS': re.compile(r'aut-num:\s+(.*)\r\n'),
                      'country': re.compile(r'country:\s+(.*)\r\n'),
                      'isp': re.compile(r'owner:\s+(.*)\r\n')},
           'afrinic': {'AS': re.compile(r'origin:\s+(.*)\n'),
                       'country': re.compile(r'country:\s+(.*)\n'),
                       'isp': re.compile(r'netname:\s+(.*)\n')}}


def main():
    ips = get_trace_ip(sys.argv[1])
    print(f'Tracing route to {sys.argv[1]} [{next(ips)}] from {next(ips)}')

    for ip in ips:
        result = ''
        for whois in sources:
            responce = get_whois_response(whois, ip)
            result = parse_whois_response(whois, responce)
            if result: break
        if result:
            print(f'from {whois}: {ip} | {result["AS"]} | {result["country"]} | {result["isp"]}')
        # print(get_info_by_ip(ip))


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

    return f'{ip} | {AS} | {country} | {holder}'


def get_whois_response(whois, ip):
    conn = None
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(100)
        conn.connect((addrs[whois], 43))
        conn.send(f'{ip}\r\n'.encode())
        data = ''
        while True:
            d = conn.recv(4096).decode(errors='ignore')
            data += d
            if not d: return data
    except socket.error:
        return ''
    finally:
        conn.close()


def parse_whois_response(whois, response):
    regexps = REGEXPS[whois]
    if is_another_whois(whois, response):
        return
    for target, regexp in regexps.items():
        match = regexp.search(response)
        if match:
            info[whois][target] = match.group(1)
        else:
            info[whois][target] = 'N/A'

    return info[whois]


def is_another_whois(main_whois, response):
    another_whois = copy.copy(sources)
    another_whois.remove(main_whois)
    temp_response = re.sub(r'remarks:.*?\n', '', response)
    return any([x in temp_response.lower() for x in another_whois + ['not allocated', 'not managed']])


if __name__ == '__main__':
    main()

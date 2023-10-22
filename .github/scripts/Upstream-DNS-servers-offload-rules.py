import requests
import time
import base64
from adblock_to_domain import adblock_to_domain
import yaml
import sys

download_urls = [
    "https://raw.githubusercontent.com/chenmozhijin/OpenWrt-K/main/files/etc/openclash/rule_provider/DirectRule-chenmozhijin.yaml",
    "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
    "https://raw.githubusercontent.com/chenmozhijin/OpenWrt-K/main/files/etc/openclash/rule_provider/ProxyRule-chenmozhijin.yaml",
    "https://raw.githubusercontent.com/YW5vbnltb3Vz/domain-list-community/release/gfwlist.txt",
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
    "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt",
    "https://raw.githubusercontent.com/Loukky/gfwlist-by-loukky/master/gfwlist.txt"
]

retry_count = 5
retry_wait_time = 10

content_dict = {}

key_mapping = {
    "https://raw.githubusercontent.com/chenmozhijin/OpenWrt-K/main/files/etc/openclash/rule_provider/DirectRule-chenmozhijin.yaml": "DirectRule-chenmozhijin",
    "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf": "accelerated-domains-china",
    "https://raw.githubusercontent.com/chenmozhijin/OpenWrt-K/main/files/etc/openclash/rule_provider/ProxyRule-chenmozhijin.yaml": "ProxyRule-chenmozhijin",
    "https://raw.githubusercontent.com/YW5vbnltb3Vz/domain-list-community/release/gfwlist.txt": "base64_YW5vbnltb3Vz",
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt": "Loyalsoldier",
    "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt": "base64_gfwlist",
    "https://raw.githubusercontent.com/Loukky/gfwlist-by-loukky/master/gfwlist.txt": "base64_Loukky"
}

for url in download_urls:
    retry = 0
    while retry < retry_count:
        response = requests.get(url)
        if response.status_code == 200:
            key = key_mapping[url]
            content = response.content
            if key.startswith("base64_"):
                key = key[len("base64_"):]
                content = base64.b64decode(content).decode('utf-8')
            content_dict[key] = content
            print(f"获取 {url} 内容成功")
            break
        else:
            print(f"获取 {url} 内容失败，状态码: {response.status_code}，尝试重试...")
            retry += 1
            time.sleep(retry_wait_time)
    if retry == retry_count:
        print(f"无法获取 {url} 内容，已尝试 {retry_count} 次")
        sys.exit(1)

China_domain_lists = []
Overseas_domain_lists = []


def extract_domain_values_from_yaml(yaml_data):
    data = yaml.safe_load(yaml_data)  # 解析YAML数据

    # 获取payload下的域名
    payload = data.get("payload", [])
    domain_list = []

    for item in payload:
        if isinstance(item, str):
            parts = item.strip().split(",")
            if len(parts) == 2:
                if parts[0] == "DOMAIN-SUFFIX":
                    domain_list.append(parts[1])
                elif parts[0] == "DOMAIN":
                    domain_list.append(parts[1])

    return domain_list


def remove_duplicates(overseas_domain_lists, china_domain_lists):
    temp_overseas_domain_list = overseas_domain_lists.copy()
    domain_count = len(overseas_domain_lists)
    for i, overseas_domain in enumerate(overseas_domain_lists):
        print(f"Processing {i}/{domain_count}", end="\r")
        for china_domain in china_domain_lists:
            if overseas_domain == china_domain or overseas_domain.endswith("." + china_domain):
                temp_overseas_domain_list.remove(overseas_domain)
                break
    return temp_overseas_domain_list


for key, content in content_dict.items():
    if isinstance(content, bytes):
        content = content.decode('utf-8')
    if key in ['gfwlist', 'YW5vbnltb3Vz', 'Loukky']:
        China_domainS, Overseas_domainS = adblock_to_domain(content)
        for China_domain in China_domainS:
            China_domain_lists.append(China_domain)
        for Overseas_domain in Overseas_domainS:
            Overseas_domain_lists.append(Overseas_domain)
    if key == 'Loyalsoldier':
        for Overseas_domain in content.split('\n'):
            Overseas_domain_lists.append(Overseas_domain)
    if key == 'DirectRule-chenmozhijin':
        for China_domain in extract_domain_values_from_yaml(content):
            China_domain_lists.append(China_domain)
    if key == 'ProxyRule-chenmozhijin':
        for Overseas_domain in extract_domain_values_from_yaml(content):
            Overseas_domain_lists.append(Overseas_domain)
    if key == 'accelerated-domains-china':
        for rule in content.split('\n'):
            if rule.startswith("server="):
                China_domain = rule.split("/")[1]
                China_domain_lists.append(China_domain)
print("开始去重")
China_domain_lists = sorted(list(set(China_domain_lists)))
Overseas_domain_lists = sorted(list(set(Overseas_domain_lists)))
print("删除Overseas_domain_lists中的China_domain_lists内容")
Overseas_domain_lists = remove_duplicates(Overseas_domain_lists, China_domain_lists)

Upstream_DNS_servers_offload_rules = '127.0.0.1:6053\n127.0.0.1:5335\n[/'

for China_domain in China_domain_lists:
    Upstream_DNS_servers_offload_rules = Upstream_DNS_servers_offload_rules + China_domain + '/'
Upstream_DNS_servers_offload_rules = Upstream_DNS_servers_offload_rules + ']127.0.0.1:6053\n[/'

for Overseas_domai in Overseas_domain_lists:
    Upstream_DNS_servers_offload_rules = Upstream_DNS_servers_offload_rules + Overseas_domai + '/'
Upstream_DNS_servers_offload_rules = Upstream_DNS_servers_offload_rules + ']127.0.0.1:5335\n'

open('AdGuardHome-dnslist(by cmzj).yaml', 'w', encoding='utf-8').write(Upstream_DNS_servers_offload_rules)
print("生成文件成功")

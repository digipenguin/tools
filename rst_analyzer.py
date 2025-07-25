from scapy.all import rdpcap, TCP, IP
from collections import defaultdict, Counter
import sys

if len(sys.argv) != 2:
    print("用法: python3 rst_analyzer.py <yourfile.pcap>")
    sys.exit(1)

pcap_file = sys.argv[1]
packets = rdpcap(pcap_file)

syn_counter = Counter()
rst_counter = Counter()
port_rst_map = defaultdict(list)
rst_in_handshake = []

for pkt in packets:
    if IP in pkt and TCP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags

        # SYN only
        if flags == "S":
            syn_counter[src] += 1

        # RST flag
        if flags & 0x04:
            rst_counter[src] += 1
            port_rst_map[src].append(dport)

        # RST during handshake (SYN sent, but response is RST)
        if flags == "RA":  # RST+ACK
            rst_in_handshake.append((src, dst, sport, dport))

print("\n🔍 Top SYN 發送 IPs:")
for ip, count in syn_counter.most_common(10):
    print(f"{ip:>16} 發送 SYN 次數：{count}")

print("\n🧨 Top RST 發送 IPs:")
for ip, count in rst_counter.most_common(10):
    print(f"{ip:>16} 發送 RST 次數：{count}")

print("\n📦 每個 IP 發 RST 的目的 TCP port：")
for ip, ports in port_rst_map.items():
    port_stats = Counter(ports).most_common(3)
    port_summary = ", ".join([f"port {p} ({c}x)" for p, c in port_stats])
    print(f"{ip:>16} → {port_summary}")

print("\n🚨 可能為 handshake 階段收到 RST 的流量:")
for src, dst, sport, dport in rst_in_handshake[:20]:  # Show only first 20
    print(f"  {dst}:{dport} 發出 RST → {src}:{sport}（可能為拒絕連線）")

# Suspicious logic
print("\n🚩 懷疑為 SYN flood 的 IPs（SYN 多，SYN-ACK / RST 少）:")
for ip in syn_counter:
    syn = syn_counter[ip]
    rst = rst_counter.get(ip, 0)
    ratio = rst / syn if syn else 0
    if syn >= 100 and ratio < 0.4:
        print(f"  {ip}: 發送 {syn} 個 SYN，但只有 {rst} 個 RST（比例 {ratio:.2f}）")


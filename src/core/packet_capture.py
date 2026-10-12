"""
Packet capture abstraction: handles live network sniffing via Scapy and
synthetic packet injection for testing, safe simulations, and demonstration modes.
"""
import threading
import time
from typing import Callable, Optional, Dict, Any

try:
    from scapy.all import sniff, AsyncSniffer, ARP, IP, TCP, UDP, DNS, DNSRR, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class PacketCapture:
    def __init__(self, interface: str, packet_callback: Callable[[Dict[str, Any]], None]):
        self.interface = interface
        self.packet_callback = packet_callback
        self.is_running = False
        self._sniffer = None
        self._thread: Optional[threading.Thread] = None

    def start_live(self):
        """Starts live packet capture on interface."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Live capture requires 'scapy'.")

        self.is_running = True
        try:
            # We filter for ARP, DNS (port 53), and TLS/HTTP (port 80, 443)
            bpf_filter = "arp or (udp and port 53) or (tcp and (port 80 or port 443))"
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=bpf_filter,
                prn=self._process_scapy_packet,
                store=False
            )
            self._sniffer.start()
        except Exception as e:
            self.is_running = False
            raise RuntimeError(f"Failed to start packet capture on {self.interface}: {e}")

    def stop(self):
        """Stops capture."""
        self.is_running = False
        if self._sniffer and self._sniffer.running:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    def feed_packet(self, normalized_pkt: Dict[str, Any]):
        """Feed a normalized packet directly (used by simulator and unit tests)."""
        self.packet_callback(normalized_pkt)

    def _process_scapy_packet(self, pkt):
        """Normalizes a raw Scapy packet into an agnostic structured dictionary."""
        try:
            norm: Dict[str, Any] = {
                "timestamp": time.time(),
                "summary": pkt.summary(),
                "layers": []
            }

            # ARP Layer
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                norm["type"] = "ARP"
                norm["arp_op"] = "request" if arp.op == 1 else "reply"
                norm["src_mac"] = arp.hwsrc.lower()
                norm["dst_mac"] = arp.hwdst.lower()
                norm["src_ip"] = arp.psrc
                norm["dst_ip"] = arp.pdst
                norm["layers"].append("ARP")

            # DNS Layer
            elif pkt.haslayer(DNS):
                dns = pkt[DNS]
                norm["type"] = "DNS"
                norm["layers"].append("DNS")
                norm["dns_id"] = dns.id
                norm["is_response"] = dns.qr == 1
                if pkt.haslayer(IP):
                    norm["src_ip"] = pkt[IP].src
                    norm["dst_ip"] = pkt[IP].dst

                if dns.qd:
                    qname = dns.qd.qname
                    norm["query_name"] = qname.decode() if isinstance(qname, bytes) else str(qname)

                if dns.qr == 1 and dns.an:
                    answers = []
                    for i in range(dns.ancount):
                        rr = dns.an[i]
                        if hasattr(rr, 'rdata'):
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                try:
                                    rdata = rdata.decode()
                                except Exception:
                                    rdata = str(rdata)
                            answers.append(str(rdata))
                    norm["answers"] = answers

            # TCP / HTTP / TLS Layer
            elif pkt.haslayer(TCP):
                norm["type"] = "TCP"
                norm["layers"].append("TCP")
                tcp = pkt[TCP]
                norm["sport"] = tcp.sport
                norm["dport"] = tcp.dport
                if pkt.haslayer(IP):
                    norm["src_ip"] = pkt[IP].src
                    norm["dst_ip"] = pkt[IP].dst

                # Check for plaintext HTTP or TLS handshake indicator
                raw_payload = bytes(tcp.payload)
                if raw_payload:
                    if raw_payload.startswith(b"GET ") or raw_payload.startswith(b"POST "):
                        norm["type"] = "HTTP"
                        norm["http_method"] = raw_payload.split(b" ")[0].decode(errors='ignore')
                    elif len(raw_payload) > 5 and raw_payload[0] == 0x16: # TLS Handshake record
                        norm["type"] = "TLS"
                        norm["tls_handshake"] = True

            else:
                norm["type"] = "OTHER"

            self.packet_callback(norm)
        except Exception:
            pass

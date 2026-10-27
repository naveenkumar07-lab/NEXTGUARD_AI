import threading
import logging
from datetime import datetime, timezone
from collections import deque

logger = logging.getLogger(__name__)

# Attempt to import Scapy safely
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
    SCAPY_AVAILABLE = True
except Exception as e:
    logger.warning(f"Scapy import notice (packet sniffing fallback mode active): {e}")


class PacketAnalyzer:
    """
    Manages safe packet capture and protocol breakdown analysis using Scapy.
    Captures ONLY packet headers and metadata. Never stores packet payloads,
    passwords, tokens, or private contents.
    Falls back gracefully when privileged capture is unavailable.
    """

    def __init__(self, max_packet_history=100):
        self._lock = threading.Lock()
        self.is_capturing = False
        self._capture_thread = None
        self._stop_event = threading.Event()
        self.interface = None
        self.captured_packets_count = 0
        self.packet_history = deque(maxlen=max_packet_history)
        
        # Protocol breakdown counters
        self.protocol_counts = {
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "dns": 0,
            "http": 0,
            "https": 0,
            "other": 0
        }
        self.permission_error = None

    def check_availability(self):
        """
        Tests if Scapy and packet sniffing permissions are available.
        """
        if not SCAPY_AVAILABLE:
            return {
                "available": False,
                "reason": "Scapy library or native packet capture driver (Npcap/WinPcap on Windows, libpcap on Linux) is not configured.",
                "privileged": False
            }
        return {
            "available": True,
            "reason": "Packet capture subsystem ready. Requires administrator/root privileges for raw sockets on local interface.",
            "privileged": True
        }

    def start_capture(self, interface_name=None):
        """
        Starts safe packet capture on the selected interface.
        """
        with self._lock:
            if self.is_capturing:
                return {"success": False, "message": "Packet capture is already running."}

            if not SCAPY_AVAILABLE:
                return {
                    "success": False,
                    "message": "Packet capture driver not available on this platform. Interface counter mode remains active.",
                    "error": "DRIVER_MISSING"
                }

            self.interface = interface_name
            self.is_capturing = True
            self.permission_error = None
            self._stop_event.clear()

            self._capture_thread = threading.Thread(
                target=self._sniff_worker,
                name="NetGuardScapySniffer",
                daemon=True
            )
            self._capture_thread.start()

            return {
                "success": True,
                "message": f"Packet sniffing started on interface {interface_name or 'default'}",
                "interface": self.interface
            }

    def stop_capture(self):
        """
        Stops packet capture gracefully.
        """
        with self._lock:
            if not self.is_capturing:
                return {"success": False, "message": "Packet capture is not running."}

            self._stop_event.set()
            self.is_capturing = False

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2.0)

        return {"success": True, "message": "Packet capture stopped."}

    def _packet_callback(self, packet):
        """
        Extracts SAFE metadata only: protocol, ports, length, timestamp.
        NEVER extracts or stores raw payload bytes or credentials.
        """
        if self._stop_event.is_set():
            return

        with self._lock:
            self.captured_packets_count += 1
            
            proto = "other"
            src_port = None
            dst_port = None
            src_ip = "N/A"
            dst_ip = "N/A"
            pkt_len = len(packet)

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                if dst_port == 80 or src_port == 80:
                    proto = "http"
                    self.protocol_counts["http"] += 1
                elif dst_port == 443 or src_port == 443:
                    proto = "https"
                    self.protocol_counts["https"] += 1
                else:
                    proto = "tcp"
                    self.protocol_counts["tcp"] += 1
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                if DNS in packet or dst_port == 53 or src_port == 53:
                    proto = "dns"
                    self.protocol_counts["dns"] += 1
                else:
                    proto = "udp"
                    self.protocol_counts["udp"] += 1
            elif ICMP in packet:
                proto = "icmp"
                self.protocol_counts["icmp"] += 1
            else:
                self.protocol_counts["other"] += 1

            # Store sanitized safe record in memory buffer
            self.packet_history.append({
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
                "protocol": proto.upper(),
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "length_bytes": pkt_len,
            })

    def _sniff_worker(self):
        """
        Background sniffing worker using Scapy.
        Handles permission errors or OS raw socket limitations safely without crashing.
        """
        try:
            # stop_filter callback checks if stop_event is set
            sniff(
                iface=self.interface if self.interface and self.interface != "default" else None,
                prn=self._packet_callback,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False
            )
        except PermissionError as pe:
            logger.error(f"Permission denied while capturing packets: {pe}")
            with self._lock:
                self.permission_error = "Administrator / root privileges required for raw packet capture."
                self.is_capturing = False
        except Exception as e:
            logger.error(f"Packet sniffer encountered exception: {e}")
            with self._lock:
                self.permission_error = str(e)
                self.is_capturing = False

    def get_live_protocol_counts(self):
        with self._lock:
            return dict(self.protocol_counts)

    def get_status(self):
        with self._lock:
            return {
                "is_capturing": self.is_capturing,
                "scapy_available": SCAPY_AVAILABLE,
                "interface": self.interface,
                "captured_packets_count": self.captured_packets_count,
                "protocol_counts": dict(self.protocol_counts),
                "recent_packets": list(self.packet_history)[-20:],
                "permission_error": self.permission_error,
            }


# Global singleton instance
packet_analyzer = PacketAnalyzer()

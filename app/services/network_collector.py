import time
import threading
import logging
from datetime import datetime, timezone
import psutil

logger = logging.getLogger(__name__)


class NetworkCollector:
    """
    Thread-safe network interface monitor utilizing psutil.
    Manages active collection sessions, throughput calculation,
    and background worker threads with bounded resources.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._app = None
        
        # State tracking
        self.active_interface = None
        self.is_demo_mode = False
        self.session_id = None
        self.session_uuid = None
        self.started_at = None
        self.interval = 2.0
        
        # Speed measurement state
        self._last_time = None
        self._last_bytes_recv = 0
        self._last_bytes_sent = 0
        self._last_pkts_recv = 0
        self._last_pkts_sent = 0
        
        # Latest live snapshot
        self.latest_snapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interface_name": "None",
            "is_monitoring": False,
            "is_demo": False,
            "download_speed_bps": 0.0,
            "upload_speed_bps": 0.0,
            "download_speed_mbps": 0.0,
            "upload_speed_mbps": 0.0,
            "packet_rate_pps": 0.0,
            "bytes_recv": 0,
            "bytes_sent": 0,
            "packets_recv": 0,
            "packets_sent": 0,
            "protocols": {
                "tcp": 0, "udp": 0, "icmp": 0, "dns": 0, "http": 0, "https": 0, "other": 0
            }
        }

    def get_interfaces(self):
        """
        Retrieves list of all available network interfaces on the host system.
        Includes IP addresses, MAC addresses, status, and duplex.
        """
        interfaces = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            io_counters = psutil.net_io_counters(pernic=True)
            
            for name, addr_list in addrs.items():
                stat = stats.get(name)
                io = io_counters.get(name)
                
                ipv4 = "N/A"
                mac = "N/A"
                for addr in addr_list:
                    if addr.family.name == "AF_INET" or addr.family == 2:
                        ipv4 = addr.address
                    elif "PACKET" in addr.family.name or "LINK" in addr.family.name or addr.family == -1:
                        mac = addr.address

                is_up = stat.isup if stat else False
                speed = stat.speed if stat else 0
                
                interfaces.append({
                    "name": name,
                    "ipv4": ipv4,
                    "mac": mac,
                    "is_up": is_up,
                    "speed_mbps": speed,
                    "bytes_recv": io.bytes_recv if io else 0,
                    "bytes_sent": io.bytes_sent if io else 0,
                    "packets_recv": io.packets_recv if io else 0,
                    "packets_sent": io.packets_sent if io else 0,
                })
        except Exception as e:
            logger.error(f"Error querying network interfaces: {e}")
            
        return interfaces

    def start_monitoring(self, app, interface_name=None, is_demo=False, interval=2.0, session_uuid=None):
        """
        Starts the background monitoring worker thread in a thread-safe manner.
        Prevents starting duplicate workers.
        """
        with self._lock:
            if self._running:
                return {
                    "success": False,
                    "message": "Monitoring is already active",
                    "interface": self.active_interface,
                    "is_demo": self.is_demo_mode
                }

            self._app = app
            self.interval = max(0.5, float(interval))
            self.is_demo_mode = is_demo
            self.started_at = datetime.now(timezone.utc)
            self.session_uuid = session_uuid or f"sess_{int(time.time())}"

            # Auto-select default active interface if none provided and not demo
            if not self.is_demo_mode:
                available = self.get_interfaces()
                if not interface_name:
                    active_candidates = [i["name"] for i in available if i["is_up"] and i["ipv4"] != "N/A" and not i["name"].startswith("Loopback")]
                    if active_candidates:
                        self.active_interface = active_candidates[0]
                    elif available:
                        self.active_interface = available[0]["name"]
                    else:
                        self.active_interface = "default"
                else:
                    self.active_interface = interface_name
            else:
                self.active_interface = "DEMO-VIRTUAL-INTERFACE"

            self._running = True
            self._last_time = time.time()

            # Initialize counters
            if not self.is_demo_mode:
                try:
                    counters = psutil.net_io_counters(pernic=True)
                    if self.active_interface in counters:
                        io = counters[self.active_interface]
                        self._last_bytes_recv = io.bytes_recv
                        self._last_bytes_sent = io.bytes_sent
                        self._last_pkts_recv = io.packets_recv
                        self._last_pkts_sent = io.packets_sent
                    else:
                        io = psutil.net_io_counters()
                        self._last_bytes_recv = io.bytes_recv
                        self._last_bytes_sent = io.bytes_sent
                        self._last_pkts_recv = io.packets_recv
                        self._last_pkts_sent = io.packets_sent
                except Exception as e:
                    logger.warning(f"Could not read initial counters: {e}")
                    self._last_bytes_recv = 0
                    self._last_bytes_sent = 0
                    self._last_pkts_recv = 0
                    self._last_pkts_sent = 0

            self._thread = threading.Thread(
                target=self._worker_loop,
                name="NetGuardCollectorThread",
                daemon=True
            )
            self._thread.start()

            return {
                "success": True,
                "message": f"Monitoring started on {self.active_interface}",
                "interface": self.active_interface,
                "is_demo": self.is_demo_mode,
                "session_uuid": self.session_uuid
            }

    def stop_monitoring(self):
        """
        Gracefully signals the worker thread to stop and awaits completion.
        """
        with self._lock:
            if not self._running:
                return {"success": False, "message": "Monitoring is not currently active"}

            self._running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

        with self._lock:
            self.latest_snapshot["is_monitoring"] = False

        return {"success": True, "message": "Monitoring stopped successfully"}

    def is_active(self):
        with self._lock:
            return self._running

    def get_snapshot(self):
        with self._lock:
            return dict(self.latest_snapshot)

    def _worker_loop(self):
        """
        Main worker execution loop executing periodically.
        Persists metrics into database and triggers anomaly checks.
        """
        from app.services.demo_generator import demo_generator
        from app.services.anomaly_detector import anomaly_detector
        from app.services.packet_analyzer import packet_analyzer

        logger.info(f"Collector worker loop started for interface {self.active_interface}")

        while True:
            with self._lock:
                if not self._running:
                    break
                interval = self.interval
                is_demo = self.is_demo_mode
                interface = self.active_interface

            now = time.time()
            elapsed = max(0.001, now - (self._last_time or now - interval))
            self._last_time = now

            if is_demo:
                # Generate realistic synthetic network telemetry
                metric_data = demo_generator.generate_tick(elapsed_seconds=elapsed)
            else:
                # Read actual psutil counters
                try:
                    counters = psutil.net_io_counters(pernic=True)
                    if interface in counters:
                        io = counters[interface]
                    else:
                        io = psutil.net_io_counters()

                    cur_recv = io.bytes_recv
                    cur_sent = io.bytes_sent
                    cur_precv = io.packets_recv
                    cur_psent = io.packets_sent

                    delta_recv = max(0, cur_recv - self._last_bytes_recv)
                    delta_sent = max(0, cur_sent - self._last_bytes_sent)
                    delta_precv = max(0, cur_precv - self._last_pkts_recv)
                    delta_psent = max(0, cur_psent - self._last_pkts_sent)

                    self._last_bytes_recv = cur_recv
                    self._last_bytes_sent = cur_sent
                    self._last_pkts_recv = cur_precv
                    self._last_pkts_sent = cur_psent

                    down_bps = delta_recv / elapsed
                    up_bps = delta_sent / elapsed
                    down_mbps = (down_bps * 8) / (1000 * 1000)
                    up_mbps = (up_bps * 8) / (1000 * 1000)
                    pkt_rate = (delta_precv + delta_psent) / elapsed

                    # Protocol breakdown (from Scapy if active, or estimated based on open ports)
                    proto_counts = packet_analyzer.get_live_protocol_counts()

                    metric_data = {
                        "interface_name": interface,
                        "is_demo": False,
                        "bytes_recv": cur_recv,
                        "bytes_sent": cur_sent,
                        "packets_recv": cur_precv,
                        "packets_sent": cur_psent,
                        "download_speed_bps": down_bps,
                        "upload_speed_bps": up_bps,
                        "download_speed_mbps": down_mbps,
                        "upload_speed_mbps": up_mbps,
                        "packet_rate_pps": pkt_rate,
                        "protocols": proto_counts
                    }
                except Exception as e:
                    logger.error(f"Error collecting real network telemetry: {e}")
                    metric_data = {
                        "interface_name": interface,
                        "is_demo": False,
                        "bytes_recv": self._last_bytes_recv,
                        "bytes_sent": self._last_bytes_sent,
                        "packets_recv": self._last_pkts_recv,
                        "packets_sent": self._last_pkts_sent,
                        "download_speed_bps": 0.0,
                        "upload_speed_bps": 0.0,
                        "download_speed_mbps": 0.0,
                        "upload_speed_mbps": 0.0,
                        "packet_rate_pps": 0.0,
                        "protocols": {"tcp": 0, "udp": 0, "icmp": 0, "dns": 0, "http": 0, "https": 0, "other": 0}
                    }

            # Update live snapshot
            with self._lock:
                self.latest_snapshot = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "interface_name": self.active_interface,
                    "is_monitoring": True,
                    "is_demo": self.is_demo_mode,
                    **metric_data
                }

            # Persist to database within app context and evaluate anomalies
            if self._app:
                try:
                    with self._app.app_context():
                        from app.models import NetworkMetric, MonitoringSession
                        from app.extensions import db

                        # Find or link session
                        session_record = None
                        if self.session_uuid:
                            session_record = MonitoringSession.query.filter_by(session_uuid=self.session_uuid).first()
                            if session_record:
                                session_record.total_bytes_recv = metric_data.get("bytes_recv", 0)
                                session_record.total_bytes_sent = metric_data.get("bytes_sent", 0)
                                session_record.total_packets = metric_data.get("packets_recv", 0) + metric_data.get("packets_sent", 0)

                        protocols = metric_data.get("protocols", {})
                        metric_row = NetworkMetric(
                            session_id=session_record.id if session_record else None,
                            interface_name=metric_data.get("interface_name", "unknown"),
                            is_demo=metric_data.get("is_demo", False),
                            bytes_recv=metric_data.get("bytes_recv", 0),
                            bytes_sent=metric_data.get("bytes_sent", 0),
                            packets_recv=metric_data.get("packets_recv", 0),
                            packets_sent=metric_data.get("packets_sent", 0),
                            download_speed_bps=metric_data.get("download_speed_bps", 0.0),
                            upload_speed_bps=metric_data.get("upload_speed_bps", 0.0),
                            download_speed_mbps=metric_data.get("download_speed_mbps", 0.0),
                            upload_speed_mbps=metric_data.get("upload_speed_mbps", 0.0),
                            packet_rate_pps=metric_data.get("packet_rate_pps", 0.0),
                            tcp_packets=protocols.get("tcp", 0),
                            udp_packets=protocols.get("udp", 0),
                            icmp_packets=protocols.get("icmp", 0),
                            dns_packets=protocols.get("dns", 0),
                            http_packets=protocols.get("http", 0),
                            https_packets=protocols.get("https", 0),
                            other_packets=protocols.get("other", 0),
                        )
                        db.session.add(metric_row)
                        db.session.commit()

                        # Evaluate anomalies (rule-based + ML)
                        anomaly_detector.evaluate_metric(
                            metric_row=metric_row,
                            session_id=session_record.id if session_record else None,
                            is_demo=metric_data.get("is_demo", False)
                        )

                except Exception as e:
                    logger.error(f"Error persisting metric or evaluating anomaly: {e}")

            time.sleep(interval)

        logger.info("Collector worker loop stopped")


# Global singleton instance
collector = NetworkCollector()

import time
import math
import random
import logging

logger = logging.getLogger(__name__)


class DemoGenerator:
    """
    High-fidelity synthetic network traffic generator.
    Produces mathematically sound throughput curves, realistic protocol
    distributions, and controllable security scenario anomalies.
    """

    SCENARIO_NORMAL = "NORMAL"
    SCENARIO_TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    SCENARIO_PORT_SCAN = "PORT_SCAN"
    SCENARIO_DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SCENARIO_DDOS_ATTACK = "DDOS_ATTACK"

    AVAILABLE_SCENARIOS = [
        SCENARIO_NORMAL,
        SCENARIO_TRAFFIC_SPIKE,
        SCENARIO_PORT_SCAN,
        SCENARIO_DATA_EXFILTRATION,
        SCENARIO_DDOS_ATTACK,
    ]

    def __init__(self):
        self.current_scenario = self.SCENARIO_NORMAL
        self.ticks = 0
        
        # Cumulative byte and packet counters
        self.cumulative_bytes_recv = 1024 * 1024 * 250  # start at 250 MB
        self.cumulative_bytes_sent = 1024 * 1024 * 80   # start at 80 MB
        self.cumulative_pkts_recv = 180000
        self.cumulative_pkts_sent = 90000

    def set_scenario(self, scenario_name: str):
        if scenario_name in self.AVAILABLE_SCENARIOS:
            self.current_scenario = scenario_name
            logger.info(f"Demo scenario switched to: {scenario_name}")
            return True
        return False

    def generate_tick(self, elapsed_seconds: float = 2.0):
        """
        Generates one telemetry interval snapshot based on the current active scenario.
        """
        self.ticks += 1
        t = self.ticks * 0.15

        # Base sinusoidal wave to mimic organic user traffic oscillation
        base_down = 18.0 + (8.0 * math.sin(t)) + (random.uniform(-2.0, 2.0))
        base_up = 4.5 + (2.0 * math.cos(t * 0.8)) + (random.uniform(-0.5, 0.8))
        base_pps = 420.0 + (120.0 * math.sin(t * 1.2)) + (random.uniform(-30, 40))

        # Protocol distribution baseline percentages
        tcp_pct = 0.55
        udp_pct = 0.20
        https_pct = 0.18
        http_pct = 0.03
        dns_pct = 0.02
        icmp_pct = 0.01
        other_pct = 0.01

        # Scenario overrides
        if self.current_scenario == self.SCENARIO_TRAFFIC_SPIKE:
            # Massive download spike (e.g. 140 - 180 Mbps)
            base_down = random.uniform(140.0, 195.0)
            base_up = random.uniform(8.0, 15.0)
            base_pps = random.uniform(1800.0, 3200.0)
            https_pct = 0.70
            tcp_pct = 0.20

        elif self.current_scenario == self.SCENARIO_DATA_EXFILTRATION:
            # Massive outbound upload spike (e.g. 75 - 120 Mbps)
            base_down = random.uniform(5.0, 12.0)
            base_up = random.uniform(75.0, 115.0)
            base_pps = random.uniform(1500.0, 2600.0)
            tcp_pct = 0.85
            https_pct = 0.10

        elif self.current_scenario == self.SCENARIO_PORT_SCAN:
            # High packet rate, rapid TCP SYN attempts, small payload
            base_down = random.uniform(2.0, 6.0)
            base_up = random.uniform(2.0, 5.0)
            base_pps = random.uniform(4200.0, 6500.0)
            tcp_pct = 0.88
            udp_pct = 0.08
            dns_pct = 0.02

        elif self.current_scenario == self.SCENARIO_DDOS_ATTACK:
            # Critical volumetric DDoS flood: high PPS, high UDP/ICMP ratio
            base_down = random.uniform(220.0, 350.0)
            base_up = random.uniform(15.0, 30.0)
            base_pps = random.uniform(8500.0, 14000.0)
            udp_pct = 0.50
            icmp_pct = 0.35
            tcp_pct = 0.12

        # Ensure positive values
        down_mbps = max(0.2, base_down)
        up_mbps = max(0.1, base_up)
        pps = max(10.0, base_pps)

        # Convert Mbps to Bytes/sec: (mbps * 1,000,000) / 8
        down_bps = (down_mbps * 1000 * 1000) / 8.0
        up_bps = (up_mbps * 1000 * 1000) / 8.0

        # Increment cumulative counters
        delta_recv_bytes = int(down_bps * elapsed_seconds)
        delta_sent_bytes = int(up_bps * elapsed_seconds)
        delta_pkts = int(pps * elapsed_seconds)
        delta_recv_pkts = int(delta_pkts * 0.7)
        delta_sent_pkts = max(1, delta_pkts - delta_recv_pkts)

        self.cumulative_bytes_recv += delta_recv_bytes
        self.cumulative_bytes_sent += delta_sent_bytes
        self.cumulative_pkts_recv += delta_recv_pkts
        self.cumulative_pkts_sent += delta_sent_pkts

        # Compute realistic protocol packets for this interval
        total_interval_pkts = delta_pkts
        proto_breakdown = {
            "tcp": int(total_interval_pkts * tcp_pct),
            "udp": int(total_interval_pkts * udp_pct),
            "icmp": int(total_interval_pkts * icmp_pct),
            "dns": int(total_interval_pkts * dns_pct),
            "http": int(total_interval_pkts * http_pct),
            "https": int(total_interval_pkts * https_pct),
            "other": int(total_interval_pkts * other_pct),
        }

        return {
            "interface_name": "DEMO-SYNTHETIC-INTERFACE",
            "is_demo": True,
            "scenario": self.current_scenario,
            "bytes_recv": self.cumulative_bytes_recv,
            "bytes_sent": self.cumulative_bytes_sent,
            "packets_recv": self.cumulative_pkts_recv,
            "packets_sent": self.cumulative_pkts_sent,
            "download_speed_bps": down_bps,
            "upload_speed_bps": up_bps,
            "download_speed_mbps": down_mbps,
            "upload_speed_mbps": up_mbps,
            "packet_rate_pps": pps,
            "protocols": proto_breakdown
        }


# Global singleton instance
demo_generator = DemoGenerator()

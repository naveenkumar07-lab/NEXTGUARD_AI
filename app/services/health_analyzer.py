import time
import socket
import logging
from datetime import datetime, timezone
import numpy as np

logger = logging.getLogger(__name__)


class NetworkHealthAnalyzer:
    """
    Evaluates real-time network health:
    - TCP socket handshake latency to configurable target
    - Successive latency probes to measure jitter (standard deviation or mean successive difference)
    - Probe failure rate as packet loss estimate
    - Computes Composite Health Score (0-100)
    - Diagnostic bottleneck identification and troubleshooting guidance
    """

    def __init__(self):
        self.default_target = "8.8.8.8"
        self.default_port = 53
        self.timeout_sec = 2.0
        self.num_probes = 4

    def measure_latency_probe(self, host: str, port: int = 53, timeout: float = 2.0):
        """
        Performs a standard TCP socket connection probe to measure round-trip latency.
        Works across all operating systems without requiring raw ICMP root permissions.
        """
        t_start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            t_end = time.perf_counter()
            latency_ms = (t_end - t_start) * 1000.0
            return latency_ms, True
        except Exception as e:
            logger.debug(f"Probe to {host}:{port} failed: {e}")
            return None, False
        finally:
            sock.close()

    def run_health_check(self, target_host: str = None, target_port: int = 53, is_demo: bool = False):
        """
        Runs multiple probes to calculate latency, jitter, loss, and composite health score.
        """
        target = target_host or self.default_target

        if is_demo:
            # Deterministic, realistic simulated health response
            latency_ms = 18.5 + (np.random.rand() * 4.0)
            jitter_ms = 2.1 + (np.random.rand() * 1.2)
            packet_loss_pct = 0.0
            health_score = 96.5
            status_label = "EXCELLENT"
            bottlenecks = "None detected. Network latency is nominal."
            recommendations = "Operational conditions optimal. Baseline continuous monitoring active."

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target_host": target,
                "health_score": round(health_score, 1),
                "latency_ms": round(latency_ms, 2),
                "jitter_ms": round(jitter_ms, 2),
                "packet_loss_pct": packet_loss_pct,
                "status_label": status_label,
                "bottlenecks": bottlenecks,
                "recommendations": recommendations,
                "is_demo": True
            }

        latencies = []
        failures = 0

        for _ in range(self.num_probes):
            lat, success = self.measure_latency_probe(target, target_port, self.timeout_sec)
            if success and lat is not None:
                latencies.append(lat)
            else:
                failures += 1
            time.sleep(0.05)

        loss_pct = (failures / self.num_probes) * 100.0

        if not latencies:
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target_host": target,
                "health_score": 0.0,
                "latency_ms": None,
                "jitter_ms": None,
                "packet_loss_pct": 100.0,
                "status_label": "CRITICAL",
                "bottlenecks": "Target host unreachable or DNS/gateway resolution failing.",
                "recommendations": "Verify default gateway route, physical/Wi-Fi connection, and DNS configuration.",
                "is_demo": False
            }

        avg_latency = float(np.mean(latencies))
        
        # Jitter: mean absolute difference between successive probes
        if len(latencies) > 1:
            diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
            jitter_ms = float(np.mean(diffs))
        else:
            jitter_ms = 0.0

        # ==========================================
        # FORMULA FOR HEALTH SCORE (0 to 100)
        # ==========================================
        # Base: 100
        # Latency penalty: 0 if < 20ms, linear degradation up to 250ms (max -40 points)
        # Jitter penalty: 0 if < 5ms, linear degradation up to 50ms (max -30 points)
        # Loss penalty: 1% loss = -3 points (max -30 points)
        score = 100.0

        # Latency component
        if avg_latency > 20.0:
            lat_penalty = min(40.0, ((avg_latency - 20.0) / 230.0) * 40.0)
            score -= lat_penalty

        # Jitter component
        if jitter_ms > 5.0:
            jit_penalty = min(30.0, ((jitter_ms - 5.0) / 45.0) * 30.0)
            score -= jit_penalty

        # Packet loss component
        loss_penalty = min(30.0, (loss_pct / 100.0) * 30.0 * 3.33)
        score -= loss_penalty

        health_score = max(0.0, min(100.0, score))

        # Status categorization
        if health_score >= 90:
            status_label = "EXCELLENT"
            bottlenecks = "None. Latency and packet stability are exemplary."
            recommendations = "Maintain current routing configurations."
        elif health_score >= 75:
            status_label = "GOOD"
            bottlenecks = "Minor latency fluctuations observed."
            recommendations = "Normal operations. Check for intermittent Wi-Fi or background downloads."
        elif health_score >= 50:
            status_label = "FAIR"
            bottlenecks = "Elevated latency or jitter detected."
            recommendations = "Check router hop latency, local queue bufferbloat, or network link saturation."
        elif health_score >= 25:
            status_label = "POOR"
            bottlenecks = "Significant jitter or packet drops degrading connectivity."
            recommendations = "Investigate local gateway load, check ISP status, restart network interface."
        else:
            status_label = "CRITICAL"
            bottlenecks = "Severe connection degradation or packet loss."
            recommendations = "Urgent diagnostic required: verify cable/interface status, DNS servers, and firewall rules."

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_host": target,
            "health_score": round(health_score, 1),
            "latency_ms": round(avg_latency, 2),
            "jitter_ms": round(jitter_ms, 2),
            "packet_loss_pct": round(loss_pct, 1),
            "status_label": status_label,
            "bottlenecks": bottlenecks,
            "recommendations": recommendations,
            "is_demo": False
        }


# Global singleton instance
health_analyzer = NetworkHealthAnalyzer()

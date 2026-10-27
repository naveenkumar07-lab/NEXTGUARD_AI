from flask import Blueprint, render_template, request
import psutil
from app.routes.auth import login_required

connections_bp = Blueprint("connections", __name__)


@connections_bp.route("/connections")
@login_required
def connections_page():
    proto_filter = request.args.get("proto", "ALL").upper()
    status_filter = request.args.get("status", "ALL").upper()
    search_query = request.args.get("q", "").strip().lower()

    connections_list = []
    permission_limited = False

    try:
        # psutil.net_connections requires admin on Windows for all sockets;
        # otherwise returns available socket connections for accessible processes.
        raw_conns = psutil.net_connections(kind="inet")
        
        for c in raw_conns:
            # Protocol
            proto = "TCP" if c.type == psutil.SOCK_STREAM else "UDP" if c.type == psutil.SOCK_DGRAM else "OTHER"
            
            # Local address
            local_addr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
            # Remote address
            remote_addr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
            
            conn_status = c.status if c.status else "NONE"
            pid = c.pid
            proc_name = "Unknown"

            if pid:
                try:
                    p = psutil.Process(pid)
                    proc_name = p.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "Protected Process"

            item = {
                "proto": proto,
                "local_addr": local_addr,
                "remote_addr": remote_addr,
                "status": conn_status,
                "pid": pid or "N/A",
                "proc_name": proc_name,
            }

            # Apply filters
            if proto_filter != "ALL" and proto != proto_filter:
                continue
            if status_filter != "ALL" and conn_status != status_filter:
                continue
            if search_query:
                haystack = f"{local_addr} {remote_addr} {proc_name} {pid}".lower()
                if search_query not in haystack:
                    continue

            connections_list.append(item)

    except (psutil.AccessDenied, PermissionError):
        permission_limited = True
    except Exception as e:
        permission_limited = True

    return render_template(
        "connections.html",
        active_page="connections",
        connections=connections_list[:150],  # bounded to top 150 for responsive rendering
        total_count=len(connections_list),
        permission_limited=permission_limited,
        proto_filter=proto_filter,
        status_filter=status_filter,
        search_query=search_query,
    )

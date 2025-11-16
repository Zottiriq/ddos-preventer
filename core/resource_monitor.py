import time
import psutil
from collections import deque

class ResourceMonitor:
    def __init__(self, log_path="/var/log/resource.log"):
        self.log_path = log_path

        # 1 saatlik kayıtlar (3600 saniye)
        self.cpu_hour = deque(maxlen=3600)
        self.ram_hour = deque(maxlen=3600)
        self.conn_hour = deque(maxlen=3600)

        # 24 saatlik kayıtlar (86400 saniye)
        self.cpu_day = deque(maxlen=86400)
        self.ram_day = deque(maxlen=86400)
        self.conn_day = deque(maxlen=86400)

        # MAX değerleri ve saatleri
        self.cpu_1h_max = 0
        self.cpu_1h_max_time = None

        self.cpu_24h_max = 0
        self.cpu_24h_max_time = None

        self.ram_1h_max = 0
        self.ram_1h_max_time = None

        self.ram_24h_max = 0
        self.ram_24h_max_time = None

        self.conn_1h_max = 0
        self.conn_1h_max_time = None

        self.conn_24h_max = 0
        self.conn_24h_max_time = None

        self.last_net = psutil.net_io_counters()
        self.last_net_time = time.time()

    def get_active_connections(self):
        try:
            return len(psutil.net_connections())
        except:
            return 0

    def update(self):
        now = time.time()
        t = time.strftime("%H:%M:%S")

        # ---- Ölçümler ----
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        conn = self.get_active_connections()

        # ---- NET IN / OUT ----
        net_now = psutil.net_io_counters()
        dt = max(now - self.last_net_time, 0.001)

        net_in = (net_now.bytes_recv - self.last_net.bytes_recv) / dt
        net_out = (net_now.bytes_sent - self.last_net.bytes_sent) / dt

        self.last_net = net_now
        self.last_net_time = now

        # ---- 1 SAATLİK KAYIT ----
        self.cpu_hour.append((cpu, now))
        self.ram_hour.append((ram, now))
        self.conn_hour.append((conn, now))

        # ---- 24 SAATLİK KAYIT ----
        self.cpu_day.append((cpu, now))
        self.ram_day.append((ram, now))
        self.conn_day.append((conn, now))

        # ---- CPU MAX GÜNCELLEME ----
        if cpu > self.cpu_1h_max:
            self.cpu_1h_max = cpu
            self.cpu_1h_max_time = t

        if cpu > self.cpu_24h_max:
            self.cpu_24h_max = cpu
            self.cpu_24h_max_time = t

        # ---- RAM MAX GÜNCELLEME ----
        if ram > self.ram_1h_max:
            self.ram_1h_max = ram
            self.ram_1h_max_time = t

        if ram > self.ram_24h_max:
            self.ram_24h_max = ram
            self.ram_24h_max_time = t

        # ---- CONN MAX GÜNCELLEME ----
        if conn > self.conn_1h_max:
            self.conn_1h_max = conn
            self.conn_1h_max_time = t

        if conn > self.conn_24h_max:
            self.conn_24h_max = conn
            self.conn_24h_max_time = t

        # ---- TEK SATIR LOG YAZ ----
        with open(self.log_path, "w") as f:
            f.write(
                "[RESOURCE]  "
                f"CPU:{cpu:.0f}%  RAM:{ram:.0f}%  NET_IN:{net_in/1024:.0f}KB/s  "
                f"NET_OUT:{net_out/1024:.0f}KB/s  ACTIVE_CONN:{conn}\n\n"

                f"CPU_1H_MAX:{self.cpu_1h_max}%@{self.cpu_1h_max_time}   "
                f"CPU_24H_MAX:{self.cpu_24h_max}%@{self.cpu_24h_max_time}\n"

                f"RAM_1H_MAX:{self.ram_1h_max}%@{self.ram_1h_max_time}   "
                f"RAM_24H_MAX:{self.ram_24h_max}%@{self.ram_24h_max_time}\n"

                f"CONN_1H_MAX:{self.conn_1h_max}@{self.conn_1h_max_time}   "
                f"CONN_24H_MAX:{self.conn_24h_max}@{self.conn_24h_max_time}"
            )

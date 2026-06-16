"""
XDR Platform — Production Agent
Lightweight log collector with buffering, compression, and resilience.
"""
import asyncio
import json
import socket
import time
import zlib
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import deque


@dataclass
class LogEntry:
    """Structured log entry for transmission."""
    timestamp: str
    hostname: str
    agent_ip: str
    source: str
    raw_log: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "agent_ip": self.agent_ip,
            "source": self.source,
            "raw_log": self.raw_log,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def compressed(self) -> bytes:
        """Compress log entry for efficient transmission."""
        return zlib.compress(self.to_json().encode("utf-8"))


class LogCollector:
    """
    Asynchronous log collector with file tailing and buffering.
    """

    def __init__(
        self,
        log_files: List[str],
        buffer_size: int = 1000,
        batch_size: int = 100,
        flush_interval: float = 5.0,
    ):
        self.log_files = log_files
        self.buffer: deque = deque(maxlen=buffer_size)
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._running = False
        self._total_collected = 0
        self._total_dropped = 0

    async def start(self) -> None:
        """Start collecting logs from all configured files."""
        self._running = True

        # Start file watchers
        tasks = [
            asyncio.create_task(self._watch_file(log_file))
            for log_file in self.log_files
        ]

        # Start flush timer
        tasks.append(asyncio.create_task(self._flush_timer()))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _watch_file(self, filepath: str) -> None:
        """Watch a single log file for new lines."""
        path = Path(filepath)

        while self._running:
            try:
                if not path.exists():
                    await asyncio.sleep(1)
                    continue

                with open(filepath, "r") as f:
                    # Go to end of file
                    f.seek(0, 2)

                    while self._running:
                        line = f.readline()
                        if not line:
                            await asyncio.sleep(0.1)
                            continue

                        if line.strip():
                            entry = LogEntry(
                                timestamp=datetime.utcnow().isoformat(),
                                hostname=socket.gethostname(),
                                agent_ip=self._get_local_ip(),
                                source=path.name,
                                raw_log=line.strip(),
                                metadata={"file": filepath},
                            )

                            if len(self.buffer) >= self.buffer.maxlen:
                                self._total_dropped += 1
                            else:
                                self.buffer.append(entry)
                                self._total_collected += 1

            except Exception as e:
                print(f"[AGENT] Error watching {filepath}: {e}")
                await asyncio.sleep(5)

    async def _flush_timer(self) -> None:
        """Periodic flush of buffer to sender."""
        while self._running:
            await asyncio.sleep(self.flush_interval)
            await self.flush()

    async def flush(self) -> List[LogEntry]:
        """Flush current buffer and return entries."""
        entries = []
        while self.buffer:
            entries.append(self.buffer.popleft())
        return entries

    @staticmethod
    def _get_local_ip() -> str:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            "total_collected": self._total_collected,
            "total_dropped": self._total_dropped,
            "buffer_size": len(self.buffer),
            "buffer_capacity": self.buffer.maxlen,
            "drop_rate": round(self._total_dropped / max(self._total_collected, 1) * 100, 2),
        }


class UDPSender:
    """
    Reliable UDP sender with retry logic and batching.
    """

    def __init__(
        self,
        server_ip: str,
        server_port: int = 5005,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        self.server_ip = server_ip
        self.server_port = server_port
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._socket: Optional[socket.socket] = None
        self._sent_count = 0
        self._failed_count = 0

    def _get_socket(self) -> socket.socket:
        """Get or create UDP socket."""
        if self._socket is None:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.settimeout(5)
        return self._socket

    async def send(self, entry: LogEntry) -> bool:
        """Send single log entry with retry."""
        return await self.send_batch([entry])

    async def send_batch(self, entries: List[LogEntry]) -> bool:
        """Send batch of log entries."""
        if not entries:
            return True

        # Prepare batch payload
        batch_data = {
            "batch": True,
            "count": len(entries),
            "entries": [e.to_dict() for e in entries],
            "agent_hostname": socket.gethostname(),
            "sent_at": datetime.utcnow().isoformat(),
        }

        payload = json.dumps(batch_data).encode("utf-8")

        # Compress if large
        if len(payload) > 1400:
            payload = zlib.compress(payload)
            is_compressed = True
        else:
            is_compressed = False

        # Send with retry
        for attempt in range(self.max_retries):
            try:
                sock = self._get_socket()
                sock.sendto(payload, (self.server_ip, self.server_port))

                self._sent_count += len(entries)
                return True

            except Exception as e:
                print(f"[AGENT] Send failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                else:
                    self._failed_count += len(entries)
                    return False

        return False

    def get_stats(self) -> Dict[str, Any]:
        """Get sender statistics."""
        return {
            "sent": self._sent_count,
            "failed": self._failed_count,
            "success_rate": round(self._sent_count / max(self._sent_count + self._failed_count, 1) * 100, 2),
            "server": f"{self.server_ip}:{self.server_port}",
        }

    def close(self) -> None:
        """Close socket connection."""
        if self._socket:
            self._socket.close()
            self._socket = None


class XDRAgent:
    """
    Main XDR Agent orchestrating collection and transmission.
    """

    def __init__(
        self,
        server_ip: str,
        log_files: List[str],
        server_port: int = 5005,
    ):
        self.collector = LogCollector(log_files)
        self.sender = UDPSender(server_ip, server_port)
        self._running = False

    async def start(self) -> None:
        """Start the agent."""
        print(f"[AGENT] Starting XDR Agent v2.0")
        print(f"[AGENT] Server: {self.sender.server_ip}:{self.sender.server_port}")
        print(f"[AGENT] Monitoring: {self.collector.log_files}")

        self._running = True

        # Start collector
        collector_task = asyncio.create_task(self.collector.start())

        # Start sender loop
        sender_task = asyncio.create_task(self._sender_loop())

        # Start stats reporter
        stats_task = asyncio.create_task(self._stats_reporter())

        await asyncio.gather(
            collector_task,
            sender_task,
            stats_task,
            return_exceptions=True,
        )

    async def _sender_loop(self) -> None:
        """Main sender loop flushing buffer periodically."""
        while self._running:
            try:
                # Flush buffer
                entries = await self.collector.flush()

                if entries:
                    # Send in batches
                    for i in range(0, len(entries), self.collector.batch_size):
                        batch = entries[i:i + self.collector.batch_size]
                        success = await self.sender.send_batch(batch)

                        if not success:
                            # Re-queue failed entries
                            for entry in batch:
                                if len(self.collector.buffer) < self.collector.buffer.maxlen:
                                    self.collector.buffer.append(entry)

                await asyncio.sleep(self.collector.flush_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[AGENT] Sender error: {e}")
                await asyncio.sleep(5)

    async def _stats_reporter(self) -> None:
        """Periodic statistics reporting."""
        while self._running:
            try:
                await asyncio.sleep(60)

                collector_stats = self.collector.get_stats()
                sender_stats = self.sender.get_stats()

                print(f"[AGENT] Stats — Collected: {collector_stats['total_collected']}, "
                      f"Dropped: {collector_stats['total_dropped']}, "
                      f"Sent: {sender_stats['sent']}, "
                      f"Failed: {sender_stats['failed']}, "
                      f"Success Rate: {sender_stats['success_rate']}%")

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[AGENT] Stats error: {e}")

    async def stop(self) -> None:
        """Gracefully stop the agent."""
        print("[AGENT] Stopping...")
        self._running = False

        # Final flush
        entries = await self.collector.flush()
        if entries:
            await self.sender.send_batch(entries)

        self.sender.close()
        print("[AGENT] Stopped")


def main():
    """Main entry point."""
    import sys

    # Configuration
    SERVER_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
    LOG_FILES = [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/nginx/access.log",
    ]

    # Filter to existing files
    existing_logs = [f for f in LOG_FILES if Path(f).exists()]

    if not existing_logs:
        print("[AGENT] WARNING: No log files found. Using dummy mode.")
        existing_logs = ["/dev/null"]

    agent = XDRAgent(
        server_ip=SERVER_IP,
        log_files=existing_logs,
    )

    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        asyncio.run(agent.stop())


if __name__ == "__main__":
    main()

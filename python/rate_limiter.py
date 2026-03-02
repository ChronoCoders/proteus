import time
from collections import deque
from threading import Lock
from typing import Optional


class RateLimiter:
    def __init__(self, max_requests: int, time_window: float):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: deque[float] = deque()
        self.lock = Lock()

    def acquire(self) -> bool:
        with self.lock:
            now = time.time()

            while self.requests and self.requests[0] < now - self.time_window:
                self.requests.popleft()

            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True

            return False

    def wait_if_needed(self, timeout: Optional[float] = None) -> bool:
        start_time = time.time()

        while not self.acquire():
            if timeout and (time.time() - start_time) > timeout:
                return False
            time.sleep(0.1)

        return True

    def get_wait_time(self) -> float:
        with self.lock:
            if len(self.requests) < self.max_requests:
                return 0.0

            now = time.time()
            oldest_request = self.requests[0]
            wait_time = self.time_window - (now - oldest_request)

            return max(0.0, wait_time)

    def reset(self) -> None:
        with self.lock:
            self.requests.clear()

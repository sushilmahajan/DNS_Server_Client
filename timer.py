import time

class Timer():
    def __init__(self, timeout_val):
        self.default = -1
        self.start_time = self.default
        self.timeout_val = timeout_val
    def start(self):
        self.start_time = time.time()
    def stop(self):
        self.start_time = self.default
    def running(self):
        return self.start_time != self.default
    def timeout(self):
        if self.running():
            return time.time() - self.start_time >= self.timeout_val
        else:
            return False

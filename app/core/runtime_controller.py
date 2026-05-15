from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import time

from app.core.process_manager import request_stop, kill_registered_processes, stop_ollama_model, should_stop
from app.core.output import log, console, show_status, info


class RuntimeController:
    def __init__(self, max_workers: int = 3):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.futures = []
        self.started_at = time.time()

    def submit(self, name: str, func, *args, **kwargs):
        log(f"Starting: {name}")

        future = self.executor.submit(func, *args, **kwargs)
        self.futures.append(
            {
                "name": name,
                "future": future,
            }
        )

        return future

    def get_task_states(self) -> dict:
        states = {}
        
        for item in self.futures:
            future = item["future"]

            if future.running():
                state = "running"
            elif future.done():
                try:
                    future.result()
                    state = "done"
                except Exception:
                    state = "failed"
            elif future.cancelled():
                state = "cancelled"
            else:
                state = "pending"
            
            states[item["name"]] = state
        
        return states

    def status(self):
        states = self.get_task_states()
        show_status(states)
        
        elapsed = int(time.time() - self.started_at)
        minutes = elapsed // 60
        seconds = elapsed % 60
        console(f"Running time: {minutes}m {seconds}s\n")

    def stop(self):
        console("\nStopping Recon+...", "bold yellow")

        request_stop()
        kill_registered_processes()
        stop_ollama_model()

        for item in self.futures:
            item["future"].cancel()

        self.executor.shutdown(wait=False, cancel_futures=True)

        console("Stopped.", "bold green")

    def all_done(self) -> bool:
        return all(item["future"].done() for item in self.futures)
    
    def wait_for_task(self, name: str, timeout: float | None = None):
        for item in self.futures:
            if item["name"] == name:
                try:
                    return item["future"].result(timeout=timeout)
                except Exception as e:
                    log(f"[!] Task {name} failed: {e}")
                    return None
        return None
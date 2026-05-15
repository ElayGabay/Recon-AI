import os
import signal
import subprocess
import threading
import time


STOP_EVENT = threading.Event()
PROCESS_LOCK = threading.Lock()
RUNNING_PROCESSES: list[subprocess.Popen] = []


def register_process(process: subprocess.Popen) -> None:
    with PROCESS_LOCK:
        RUNNING_PROCESSES.append(process)


def unregister_process(process: subprocess.Popen) -> None:
    with PROCESS_LOCK:
        if process in RUNNING_PROCESSES:
            RUNNING_PROCESSES.remove(process)


def request_stop() -> None:
    STOP_EVENT.set()


def should_stop() -> bool:
    return STOP_EVENT.is_set()


def kill_process_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return

    try:
        if os.name == "nt":
            # Windows
            try:
                process.send_signal(signal.CTRL_BREAK_EVENT)
                time.sleep(0.3)
            except Exception:
                pass

            if process.poll() is None:
                process.terminate()
                time.sleep(0.3)

            if process.poll() is None:
                process.kill()

        else:
            # Linux / macOS
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                time.sleep(0.3)
            except Exception:
                pass

            if process.poll() is None:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except Exception:
                    process.kill()

    except Exception:
        pass


def kill_registered_processes() -> None:
    with PROCESS_LOCK:
        processes = list(RUNNING_PROCESSES)

    for process in processes:
        kill_process_tree(process)


def stop_ollama_model(model_name: str = "qwen2.5-coder:7b") -> None:
    try:
        subprocess.run(
            ["ollama", "stop", model_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
    except Exception:
        pass


def hard_exit(exit_code: int = 130) -> None:
    request_stop()
    kill_registered_processes()
    stop_ollama_model()
    os._exit(exit_code)
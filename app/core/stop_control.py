from app.core.process_manager import (
    should_stop,
    request_stop,
    STOP_EVENT,
)


def reset_stop() -> None:
    STOP_EVENT.clear()


__all__ = ["should_stop", "request_stop", "reset_stop", "STOP_EVENT"]

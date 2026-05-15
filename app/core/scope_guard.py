from urllib.parse import urlparse


class ScopeGuard:
    def __init__(self, target_url: str):
        self.allowed_host = self.get_hostname(target_url)

    def normalize_target(self, target: str) -> str:
        target = target.strip()

        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        return target.rstrip("/")

    def get_hostname(self, target: str) -> str:
        normalized = self.normalize_target(target)
        parsed = urlparse(normalized)

        if not parsed.hostname:
            raise ValueError(f"Invalid target: {target}")

        return parsed.hostname.lower()

    def is_allowed(self, target: str) -> bool:
        hostname = self.get_hostname(target)

        if hostname == self.allowed_host:
            return True

        if hostname.endswith("." + self.allowed_host):
            return True

        return False

    def require_allowed(self, target: str) -> str:
        normalized = self.normalize_target(target)

        if not self.is_allowed(normalized):
            hostname = self.get_hostname(normalized)
            raise PermissionError(
                f"Target '{hostname}' is blocked. Current allowed host is '{self.allowed_host}'."
            )

        return normalized
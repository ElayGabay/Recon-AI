import requests


class OllamaUnavailableError(Exception):
    """Raised when Ollama is not reachable or returns an error."""


class OllamaClient:
    def __init__(
        self,
        model: str = "qwen2.5-coder:7b",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.1,
        keep_alive: str = "2m",
        connect_timeout: float = 5.0,
        read_timeout: float = 180.0,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.keep_alive = keep_alive
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

    def is_available(self) -> bool:
        """Quick check whether Ollama is reachable."""
        try:
            requests.get(f"{self.base_url}/api/tags", timeout=self.connect_timeout)
            return True
        except Exception:
            return False

    def ask(self, prompt: str) -> str:
        url = f"{self.base_url}/api/generate"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": self.temperature
            }
        }

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=(self.connect_timeout, self.read_timeout),
            )
            response.raise_for_status()
        except requests.exceptions.ConnectionError as exc:
            raise OllamaUnavailableError(
                f"Cannot connect to Ollama at {self.base_url}. "
                "Make sure Ollama is running: ollama serve"
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise OllamaUnavailableError(
                f"Ollama timed out at {self.base_url}."
            ) from exc
        except requests.exceptions.HTTPError as exc:
            raise OllamaUnavailableError(
                f"Ollama returned HTTP error: {exc}"
            ) from exc

        data = response.json()
        return data.get("response", "").strip()
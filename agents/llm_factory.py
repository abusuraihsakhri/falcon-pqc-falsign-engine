"""
Inference Engine supporting local Ollama, Claude, OpenAI, and deterministic Mock with Zero-PHI checks.
"""
from .base import PHIGuard


class MockLLM:
    def __init__(self, system_name: str = "Falcon Pqc Falsign Engine"):
        self.system_name = system_name

    def invoke(self, prompt: str) -> str:
        PHIGuard.assert_no_phi(prompt)
        return f"[{self.system_name} mock]: No language model or cryptographic verification was performed. Query: '{prompt[:60]}...'"


class LLMFactory:
    """Creates configured LLM client instances with zero-PHI protection."""

    @staticmethod
    def create(provider: str = "mock", system_name: str = "Falcon Pqc Falsign Engine"):
        prov = str(provider).lower()
        if prov in ["mock", "deterministic", "test"]:
            return MockLLM(system_name)
        raise ValueError(
            f"Unsupported MODEL_PROVIDER {provider!r}; only the local mock adapter is implemented"
        )

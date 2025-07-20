"""Model configurations for OpenRouter."""

from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class ModelConfig:
    """Configuration for a specific model."""
    name: str
    display_name: str
    provider: str
    context_length: int
    cost_per_1k_input: float
    cost_per_1k_output: float
    supports_functions: bool = False
    supports_system_message: bool = True
    
    @property
    def model_id(self) -> str:
        """Get the full model ID for OpenRouter."""
        return f"{self.provider}/{self.name}"

# Model configurations
MODELS = {
    "deepseek-coder": ModelConfig(
        name="deepseek-coder",
        display_name="DeepSeek Coder",
        provider="deepseek",
        context_length=16000,
        cost_per_1k_input=0.00014,
        cost_per_1k_output=0.00028,
        supports_functions=False
    ),
    "qwen-72b-chat": ModelConfig(
        name="qwen-72b-chat",
        display_name="Qwen 72B Chat",
        provider="qwen",
        context_length=32000,
        cost_per_1k_input=0.0009,
        cost_per_1k_output=0.0009,
        supports_functions=True
    ),
    "qwen-7b-chat": ModelConfig(
        name="qwen-7b-chat",
        display_name="Qwen 7B Chat",
        provider="qwen",
        context_length=8000,
        cost_per_1k_input=0.00012,
        cost_per_1k_output=0.00012,
        supports_functions=True
    ),
    "mixtral-8x7b-instruct": ModelConfig(
        name="mixtral-8x7b-instruct",
        display_name="Mixtral 8x7B",
        provider="mistralai",
        context_length=32000,
        cost_per_1k_input=0.00027,
        cost_per_1k_output=0.00027,
        supports_functions=False
    ),
    "llama-3-70b-instruct": ModelConfig(
        name="llama-3-70b-instruct",
        display_name="Llama 3 70B",
        provider="meta-llama",
        context_length=8000,
        cost_per_1k_input=0.00059,
        cost_per_1k_output=0.00079,
        supports_functions=False
    )
}

def get_model_config(model_key: str) -> ModelConfig:
    """Get model configuration by key."""
    if model_key not in MODELS:
        raise ValueError(f"Unknown model: {model_key}")
    return MODELS[model_key]

def get_all_model_ids() -> list[str]:
    """Get all model IDs for OpenRouter."""
    return [model.model_id for model in MODELS.values()]
"""Model wrapper for consistent interface across different LLMs."""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass
import asyncio
from loguru import logger

from .openrouter_client import OpenRouterClient, ChatMessage, ChatResponse
from config.models_config import ModelConfig, get_model_config

@dataclass
class ModelRequest:
    """Structured request for model interaction."""
    prompt: str
    system_prompt: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    metadata: Dict[str, Any] = None

class ModelWrapper:
    """Unified interface for interacting with different models."""
    
    def __init__(self, model_key: str, client: Optional[OpenRouterClient] = None):
        """Initialize model wrapper."""
        self.model_key = model_key
        self.model_config = get_model_config(model_key)
        self.model_id = self.model_config.model_id
        self.client = client
        self._owned_client = False
        
    async def __aenter__(self):
        """Enter async context."""
        if not self.client:
            self.client = OpenRouterClient()
            self._owned_client = True
            await self.client.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context."""
        if self._owned_client and self.client:
            await self.client.__aexit__(exc_type, exc_val, exc_tb)
    
    def _prepare_messages(
        self,
        prompt: str,
        system_prompt: Optional[str] = None
    ) -> List[ChatMessage]:
        """Prepare messages for the model."""
        messages = []
        
        if system_prompt and self.model_config.supports_system_message:
            messages.append(ChatMessage(role="system", content=system_prompt))
        elif system_prompt:
            # Prepend system prompt to user message if not supported
            prompt = f"{system_prompt}\n\n{prompt}"
        
        messages.append(ChatMessage(role="user", content=prompt))
        return messages
    
    async def generate(self, request: ModelRequest) -> ChatResponse:
        """Generate response from the model."""
        if not self.client:
            raise RuntimeError("Client not initialized. Use async context manager.")
        
        messages = self._prepare_messages(request.prompt, request.system_prompt)
        
        logger.info(f"Generating response from {self.model_key}")
        
        response = await self.client.chat_completion(
            model=self.model_id,
            messages=messages,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            _model_configs=[self.model_config]  # Pass config for cost calculation
        )
        
        # Log token usage
        logger.debug(
            f"{self.model_key} usage: "
            f"{response.usage.total_tokens} tokens, "
            f"${response.usage.total_cost:.4f}"
        )
        
        return response
    
    async def batch_generate(
        self,
        requests: List[ModelRequest]
    ) -> List[ChatResponse]:
        """Generate responses for multiple requests."""
        tasks = [self.generate(request) for request in requests]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def supports_feature(self, feature: str) -> bool:
        """Check if model supports a specific feature."""
        return getattr(self.model_config, f"supports_{feature}", False)
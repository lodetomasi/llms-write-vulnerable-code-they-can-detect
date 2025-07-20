"""Async OpenRouter client implementation with retry logic and token tracking."""

import asyncio
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log
)
from loguru import logger
import tiktoken

from config.settings import settings
from config.models_config import ModelConfig

@dataclass
class TokenUsage:
    """Track token usage and costs."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    prompt_cost: float = 0.0
    completion_cost: float = 0.0
    total_cost: float = 0.0
    
    def add(self, other: 'TokenUsage') -> None:
        """Add another token usage to this one."""
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.total_tokens += other.total_tokens
        self.prompt_cost += other.prompt_cost
        self.completion_cost += other.completion_cost
        self.total_cost += other.total_cost

@dataclass
class ChatMessage:
    """Chat message structure."""
    role: str
    content: str

@dataclass
class ChatResponse:
    """Response from chat completion."""
    content: str
    model: str
    usage: TokenUsage
    raw_response: Dict[str, Any]
    request_id: Optional[str] = None
    latency_ms: Optional[float] = None

class OpenRouterClient:
    """Async client for OpenRouter API with advanced features."""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the client."""
        self.api_key = api_key or settings.openrouter_api_key
        self.base_url = settings.openrouter_base_url
        self.session: Optional[httpx.AsyncClient] = None
        self.total_usage = TokenUsage()
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_requests)
        
        # Initialize tokenizer for estimation
        try:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
        except Exception:
            logger.warning("Failed to load tokenizer, using approximate token counting")
            self.tokenizer = None
    
    async def __aenter__(self):
        """Enter async context."""
        self.session = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.request_timeout),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/llm-security-paradox",
                "X-Title": "LLM Security Paradox Experiment"
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context."""
        if self.session:
            await self.session.aclose()
    
    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text."""
        if self.tokenizer:
            return len(self.tokenizer.encode(text))
        else:
            # Rough estimation: 1 token per 4 characters
            return len(text) // 4
    
    def calculate_cost(self, tokens: int, is_input: bool, model_config: ModelConfig) -> float:
        """Calculate cost for tokens."""
        rate = model_config.cost_per_1k_input if is_input else model_config.cost_per_1k_output
        return (tokens / 1000) * rate
    
    @retry(
        stop=stop_after_attempt(settings.retry_max_attempts),
        wait=wait_exponential(
            multiplier=settings.retry_backoff_factor,
            min=4,
            max=60
        ),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        before_sleep=before_sleep_log(logger, "INFO")
    )
    async def _make_request(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Make HTTP request with retry logic."""
        if not self.session:
            raise RuntimeError("Client not initialized. Use async context manager.")
        
        async with self._semaphore:
            start_time = time.time()
            response = await self.session.post(
                f"{self.base_url}/{endpoint}",
                json=payload
            )
            latency_ms = (time.time() - start_time) * 1000
            
            if response.status_code == 429:
                # Rate limit - wait and retry
                retry_after = int(response.headers.get("Retry-After", 60))
                logger.warning(f"Rate limited, waiting {retry_after}s")
                await asyncio.sleep(retry_after)
                raise httpx.NetworkError("Rate limited")
            
            response.raise_for_status()
            data = response.json()
            data["_latency_ms"] = latency_ms
            return data
    
    async def chat_completion(
        self,
        model: str,
        messages: List[ChatMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> ChatResponse:
        """Send chat completion request."""
        payload = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature or settings.default_temperature,
            "max_tokens": max_tokens or settings.max_tokens,
            **kwargs
        }
        
        # Log request
        logger.debug(f"Sending request to {model}: {len(messages)} messages")
        
        try:
            response_data = await self._make_request("chat/completions", payload)
            
            # Extract response
            choice = response_data["choices"][0]
            content = choice["message"]["content"]
            
            # Calculate usage
            usage_data = response_data.get("usage", {})
            model_config = next(
                (cfg for cfg in kwargs.get("_model_configs", []) 
                 if cfg.model_id == model),
                None
            )
            
            usage = TokenUsage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0)
            )
            
            if model_config:
                usage.prompt_cost = self.calculate_cost(
                    usage.prompt_tokens, True, model_config
                )
                usage.completion_cost = self.calculate_cost(
                    usage.completion_tokens, False, model_config
                )
                usage.total_cost = usage.prompt_cost + usage.completion_cost
            
            # Update total usage
            self.total_usage.add(usage)
            
            return ChatResponse(
                content=content,
                model=model,
                usage=usage,
                raw_response=response_data,
                request_id=response_data.get("id"),
                latency_ms=response_data.get("_latency_ms")
            )
            
        except Exception as e:
            logger.error(f"Error in chat completion: {e}")
            raise
    
    async def batch_chat_completion(
        self,
        requests: List[Dict[str, Any]]
    ) -> List[ChatResponse]:
        """Send multiple chat completion requests concurrently."""
        tasks = [
            self.chat_completion(**request)
            for request in requests
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_usage_summary(self) -> Dict[str, Any]:
        """Get summary of token usage and costs."""
        return {
            "total_tokens": self.total_usage.total_tokens,
            "prompt_tokens": self.total_usage.prompt_tokens,
            "completion_tokens": self.total_usage.completion_tokens,
            "total_cost": self.total_usage.total_cost,
            "prompt_cost": self.total_usage.prompt_cost,
            "completion_cost": self.total_usage.completion_cost
        }
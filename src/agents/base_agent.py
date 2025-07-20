"""Base agent class for the dual-antagonist framework."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
import uuid

from src.llm_interface.model_wrapper import ModelWrapper, ModelRequest
from src.llm_interface.openrouter_client import ChatResponse

@dataclass
class AgentResult:
    """Result from an agent interaction."""
    agent_type: str
    model: str
    vulnerability_type: str
    prompt: str
    response: str
    success: bool
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    interaction_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "agent_type": self.agent_type,
            "model": self.model,
            "vulnerability_type": self.vulnerability_type,
            "prompt": self.prompt,
            "response": self.response,
            "success": self.success,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
            "interaction_id": self.interaction_id
        }

class BaseAgent(ABC):
    """Abstract base class for agents."""
    
    def __init__(self, model_wrapper: ModelWrapper):
        """Initialize the agent."""
        self.model_wrapper = model_wrapper
        self.interaction_history: List[AgentResult] = []
    
    @property
    @abstractmethod
    def agent_type(self) -> str:
        """Return the type of agent."""
        pass
    
    @abstractmethod
    async def interact(
        self,
        vulnerability_type: str,
        context: Dict[str, Any]
    ) -> AgentResult:
        """Interact with the model for a specific vulnerability."""
        pass
    
    async def _generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> ChatResponse:
        """Generate response from the model."""
        request = ModelRequest(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens
        )
        return await self.model_wrapper.generate(request)
    
    def _create_result(
        self,
        vulnerability_type: str,
        prompt: str,
        response: str,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AgentResult:
        """Create an agent result."""
        result = AgentResult(
            agent_type=self.agent_type,
            model=self.model_wrapper.model_key,
            vulnerability_type=vulnerability_type,
            prompt=prompt,
            response=response,
            success=success,
            metadata=metadata or {}
        )
        self.interaction_history.append(result)
        return result
    
    def get_history(self) -> List[AgentResult]:
        """Get interaction history."""
        return self.interaction_history.copy()
    
    def clear_history(self) -> None:
        """Clear interaction history."""
        self.interaction_history.clear()
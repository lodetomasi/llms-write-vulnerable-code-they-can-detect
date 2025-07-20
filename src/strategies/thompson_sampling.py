"""Thompson Sampling for optimal prompt strategy discovery."""

import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field
import json
from loguru import logger

from config.settings import STRATEGY_DIMENSIONS

@dataclass
class ArmStatistics:
    """Statistics for a multi-armed bandit arm."""
    successes: int = 0
    failures: int = 0
    
    @property
    def trials(self) -> int:
        """Total number of trials."""
        return self.successes + self.failures
    
    @property
    def success_rate(self) -> float:
        """Empirical success rate."""
        if self.trials == 0:
            return 0.0
        return self.successes / self.trials
    
    def sample_beta(self) -> float:
        """Sample from Beta distribution."""
        # Add 1 to avoid Beta(0,0)
        return np.random.beta(self.successes + 1, self.failures + 1)

@dataclass
class StrategyArm:
    """Represents a specific strategy configuration."""
    framing: str
    length: str
    temperature_modifier: float
    example_inclusion: bool
    style: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framing": self.framing,
            "length": self.length,
            "temperature_modifier": self.temperature_modifier,
            "example_inclusion": self.example_inclusion,
            "style": self.style
        }
    
    def to_key(self) -> str:
        """Convert to unique key for tracking."""
        return json.dumps(self.to_dict(), sort_keys=True)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StrategyArm':
        """Create from dictionary."""
        return cls(**data)

class ThompsonSampler:
    """Thompson Sampling for discovering optimal attack strategies."""
    
    def __init__(
        self,
        exploration_factor: float = 1.0,
        convergence_threshold: float = 0.01
    ):
        """Initialize the sampler."""
        self.exploration_factor = exploration_factor
        self.convergence_threshold = convergence_threshold
        self.arms: Dict[str, ArmStatistics] = {}
        self.history: List[Dict[str, Any]] = []
        self.iteration = 0
        
        # Initialize all possible arms
        self._initialize_arms()
    
    def _initialize_arms(self) -> None:
        """Initialize all possible strategy combinations."""
        # Create all combinations of strategy dimensions
        from itertools import product
        
        dimensions = [
            STRATEGY_DIMENSIONS["framing"],
            STRATEGY_DIMENSIONS["length"],
            STRATEGY_DIMENSIONS["temperature_modifier"],
            STRATEGY_DIMENSIONS["example_inclusion"],
            STRATEGY_DIMENSIONS["style"]
        ]
        
        for combo in product(*dimensions):
            arm = StrategyArm(
                framing=combo[0],
                length=combo[1],
                temperature_modifier=combo[2],
                example_inclusion=combo[3],
                style=combo[4]
            )
            self.arms[arm.to_key()] = ArmStatistics()
        
        logger.info(f"Initialized {len(self.arms)} strategy arms")
    
    def select_arm(self) -> StrategyArm:
        """Select an arm using Thompson Sampling."""
        # Sample from each arm's Beta distribution
        samples = {}
        for arm_key, stats in self.arms.items():
            # Apply exploration factor
            sample = stats.sample_beta() * self.exploration_factor
            samples[arm_key] = sample
        
        # Select arm with highest sample
        best_arm_key = max(samples.keys(), key=lambda k: samples[k])
        
        # Convert back to StrategyArm
        arm_dict = json.loads(best_arm_key)
        selected_arm = StrategyArm.from_dict(arm_dict)
        
        self.iteration += 1
        
        return selected_arm
    
    def update(self, arm: StrategyArm, success: bool) -> None:
        """Update arm statistics based on outcome."""
        arm_key = arm.to_key()
        
        if arm_key not in self.arms:
            logger.warning(f"Unknown arm: {arm_key}")
            return
        
        stats = self.arms[arm_key]
        if success:
            stats.successes += 1
        else:
            stats.failures += 1
        
        # Record in history
        self.history.append({
            "iteration": self.iteration,
            "arm": arm.to_dict(),
            "success": success,
            "cumulative_success_rate": stats.success_rate
        })
        
        logger.debug(
            f"Updated arm {arm.framing}-{arm.length}: "
            f"success_rate={stats.success_rate:.3f} "
            f"({stats.successes}/{stats.trials})"
        )
    
    def get_best_strategies(self, top_k: int = 5) -> List[Tuple[StrategyArm, float]]:
        """Get the best performing strategies."""
        results = []
        
        for arm_key, stats in self.arms.items():
            if stats.trials > 0:
                arm_dict = json.loads(arm_key)
                arm = StrategyArm.from_dict(arm_dict)
                results.append((arm, stats.success_rate))
        
        # Sort by success rate
        results.sort(key=lambda x: x[1], reverse=True)
        
        return results[:top_k]
    
    def has_converged(self) -> bool:
        """Check if the algorithm has converged."""
        if self.iteration < 50:  # Minimum iterations
            return False
        
        # Get success rates for all arms with sufficient trials
        active_arms = [
            stats.success_rate 
            for stats in self.arms.values() 
            if stats.trials >= 5
        ]
        
        if len(active_arms) < 5:
            return False
        
        # Check if top arm is significantly better
        success_rates = sorted(active_arms, reverse=True)
        if len(success_rates) >= 2:
            gap = success_rates[0] - success_rates[1]
            return gap > self.convergence_threshold
        
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        total_trials = sum(stats.trials for stats in self.arms.values())
        total_successes = sum(stats.successes for stats in self.arms.values())
        
        # Group by dimension
        dimension_stats = {
            "framing": {},
            "length": {},
            "temperature_modifier": {},
            "example_inclusion": {},
            "style": {}
        }
        
        for arm_key, stats in self.arms.items():
            if stats.trials > 0:
                arm_dict = json.loads(arm_key)
                for dim, value in arm_dict.items():
                    if value not in dimension_stats[dim]:
                        dimension_stats[dim][value] = {
                            "trials": 0,
                            "successes": 0
                        }
                    dimension_stats[dim][value]["trials"] += stats.trials
                    dimension_stats[dim][value]["successes"] += stats.successes
        
        # Calculate success rates by dimension
        for dim in dimension_stats:
            for value in dimension_stats[dim]:
                trials = dimension_stats[dim][value]["trials"]
                successes = dimension_stats[dim][value]["successes"]
                if trials > 0:
                    dimension_stats[dim][value]["success_rate"] = successes / trials
        
        return {
            "total_iterations": self.iteration,
            "total_trials": total_trials,
            "overall_success_rate": total_successes / total_trials if total_trials > 0 else 0,
            "converged": self.has_converged(),
            "dimension_statistics": dimension_stats,
            "best_strategies": [
                {"strategy": arm.to_dict(), "success_rate": rate}
                for arm, rate in self.get_best_strategies()
            ]
        }
    
    def save_state(self, filepath: str) -> None:
        """Save sampler state to file."""
        state = {
            "iteration": self.iteration,
            "arms": {
                arm_key: {
                    "successes": stats.successes,
                    "failures": stats.failures
                }
                for arm_key, stats in self.arms.items()
            },
            "history": self.history
        }
        
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2)
    
    def load_state(self, filepath: str) -> None:
        """Load sampler state from file."""
        with open(filepath, 'r') as f:
            state = json.load(f)
        
        self.iteration = state["iteration"]
        self.history = state["history"]
        
        # Restore arm statistics
        for arm_key, arm_data in state["arms"].items():
            if arm_key in self.arms:
                self.arms[arm_key].successes = arm_data["successes"]
                self.arms[arm_key].failures = arm_data["failures"]
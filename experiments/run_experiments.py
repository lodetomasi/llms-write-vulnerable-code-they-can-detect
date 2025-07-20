#!/usr/bin/env python3
"""Main experiment runner for LLM Security Paradox study."""

import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
import click
from loguru import logger
from tqdm.asyncio import tqdm
from datetime import datetime
import pandas as pd

from config.settings import settings, VULNERABILITY_TYPES
from config.models_config import MODELS, get_model_config
from src.llm_interface.openrouter_client import OpenRouterClient
from src.llm_interface.model_wrapper import ModelWrapper
from src.agents.defense_agent import DefenseAgent
from src.agents.attack_agent import AttackAgent
from src.vulnerabilities.sql_injection import SQLInjectionChecker
from src.vulnerabilities.os_command import OSCommandChecker
from src.vulnerabilities.xss import XSSChecker
from src.strategies.thompson_sampling import ThompsonSampler
from src.evaluation.metrics import calculate_gap_metric, calculate_resistance_score
from src.evaluation.scoring import ExperimentScorer

# Initialize vulnerability checkers
VULNERABILITY_CHECKERS = {
    "sql_injection": SQLInjectionChecker(),
    "os_command": OSCommandChecker(),
    "xss": XSSChecker()
}

class ExperimentRunner:
    """Main experiment orchestrator."""
    
    def __init__(
        self,
        models: Optional[List[str]] = None,
        vulnerabilities: Optional[List[str]] = None,
        trials: int = 20,
        max_parallel: int = 5
    ):
        """Initialize experiment runner."""
        self.models = models or list(MODELS.keys())
        self.vulnerabilities = vulnerabilities or VULNERABILITY_TYPES
        self.trials = trials
        self.max_parallel = max_parallel
        self.results = []
        self.scorer = ExperimentScorer()
        
        # Create results directory
        self.results_dir = settings.get_results_path("raw_data")
        self.checkpoint_file = self.results_dir / "checkpoint.json"
        
        logger.info(
            f"Initialized experiment runner: "
            f"{len(self.models)} models, "
            f"{len(self.vulnerabilities)} vulnerabilities, "
            f"{trials} trials each"
        )
    
    async def run_all_experiments(self) -> None:
        """Run all experiments."""
        start_time = time.time()
        
        async with OpenRouterClient() as client:
            # Create tasks for all model-vulnerability combinations
            tasks = []
            for model_key in self.models:
                for vulnerability in self.vulnerabilities:
                    task = self.run_model_vulnerability_experiment(
                        client, model_key, vulnerability
                    )
                    tasks.append(task)
            
            # Run with concurrency limit
            semaphore = asyncio.Semaphore(self.max_parallel)
            
            async def bounded_task(task):
                async with semaphore:
                    return await task
            
            # Execute all tasks with progress bar
            bounded_tasks = [bounded_task(task) for task in tasks]
            
            with tqdm(total=len(bounded_tasks), desc="Running experiments") as pbar:
                for coro in asyncio.as_completed(bounded_tasks):
                    result = await coro
                    self.results.extend(result)
                    pbar.update(1)
                    
                    # Save checkpoint
                    if len(self.results) % settings.checkpoint_interval == 0:
                        self.save_checkpoint()
        
        # Final save
        self.save_results()
        
        # Print summary
        duration = time.time() - start_time
        logger.info(f"Experiments completed in {duration:.2f} seconds")
        self.print_summary()
    
    async def run_model_vulnerability_experiment(
        self,
        client: OpenRouterClient,
        model_key: str,
        vulnerability: str
    ) -> List[Dict[str, Any]]:
        """Run experiment for a specific model-vulnerability pair."""
        logger.info(f"Starting experiment: {model_key} - {vulnerability}")
        
        results = []
        model_wrapper = ModelWrapper(model_key, client)
        
        # Phase 1: Test comprehension
        defense_agent = DefenseAgent(model_wrapper)
        comprehension_results = await self.test_comprehension(
            defense_agent, vulnerability
        )
        results.extend(comprehension_results)
        
        # Phase 2: Test generation with Thompson Sampling
        attack_agent = AttackAgent(
            model_wrapper,
            VULNERABILITY_CHECKERS[vulnerability]
        )
        
        sampler = ThompsonSampler()
        generation_results = await self.test_generation_with_thompson(
            attack_agent, vulnerability, sampler
        )
        results.extend(generation_results)
        
        return results
    
    async def test_comprehension(
        self,
        defense_agent: DefenseAgent,
        vulnerability: str
    ) -> List[Dict[str, Any]]:
        """Test model comprehension of vulnerability."""
        results = []
        
        # Get test cases
        checker = VULNERABILITY_CHECKERS[vulnerability]
        test_cases = checker.get_test_cases()
        
        for test_case in test_cases:
            context = {
                "vulnerable_code": test_case.vulnerable_code,
                "secure_code": test_case.secure_code
            }
            
            # Run comprehension tests
            comprehension_results = await defense_agent.interact(
                vulnerability, context
            )
            
            # Convert to flat results
            for test_type, result in comprehension_results.items():
                results.append({
                    "experiment_type": "comprehension",
                    "model": defense_agent.model_wrapper.model_key,
                    "vulnerability": vulnerability,
                    "test_type": test_type,
                    "test_case": test_case.name,
                    "success": result.success,
                    "prompt": result.prompt,
                    "response": result.response,
                    "metadata": result.metadata,
                    "timestamp": result.timestamp.isoformat()
                })
        
        return results
    
    async def test_generation_with_thompson(
        self,
        attack_agent: AttackAgent,
        vulnerability: str,
        sampler: ThompsonSampler
    ) -> List[Dict[str, Any]]:
        """Test generation with Thompson Sampling optimization."""
        results = []
        
        for trial in range(self.trials):
            # Select strategy using Thompson Sampling
            strategy_arm = sampler.select_arm()
            
            # Test escalation with selected strategy
            context = {
                "strategy": strategy_arm.to_dict(),
                "sophistication_level": 0  # Will test all levels
            }
            
            # Run escalation test
            escalation_results = await attack_agent.test_escalation(
                vulnerability, max_level=6
            )
            
            # Update Thompson Sampler based on results
            breakthrough_level = escalation_results["breakthrough_level"]
            success = breakthrough_level is not None
            sampler.update(strategy_arm, success)
            
            # Record results
            for level_result in escalation_results["results"]:
                results.append({
                    "experiment_type": "generation",
                    "model": attack_agent.model_wrapper.model_key,
                    "vulnerability": vulnerability,
                    "trial": trial,
                    "sophistication_level": level_result.metadata["sophistication_level"],
                    "strategy": level_result.metadata["strategy"],
                    "success": level_result.success,
                    "prompt": level_result.prompt,
                    "response": level_result.response,
                    "extracted_code": level_result.metadata.get("extracted_code"),
                    "breakthrough_level": breakthrough_level,
                    "resistance_score": escalation_results["resistance_score"],
                    "timestamp": level_result.timestamp.isoformat()
                })
            
            # Check for convergence
            if sampler.has_converged():
                logger.info(
                    f"Thompson Sampling converged after {trial + 1} trials "
                    f"for {vulnerability}"
                )
                break
        
        # Save Thompson Sampling state
        sampler_file = self.results_dir / f"thompson_{vulnerability}_{attack_agent.model_wrapper.model_key}.json"
        sampler.save_state(str(sampler_file))
        
        return results
    
    def save_checkpoint(self) -> None:
        """Save checkpoint of current results."""
        checkpoint_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "results_count": len(self.results),
            "results": self.results
        }
        
        with open(self.checkpoint_file, 'w') as f:
            json.dump(checkpoint_data, f, indent=2)
        
        logger.debug(f"Saved checkpoint with {len(self.results)} results")
    
    def save_results(self) -> None:
        """Save all results to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save raw JSON
        json_file = self.results_dir / f"experiment_results_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Save as CSV
        df = pd.DataFrame(self.results)
        csv_file = self.results_dir / f"experiment_results_{timestamp}.csv"
        df.to_csv(csv_file, index=False)
        
        logger.info(f"Saved results to {json_file} and {csv_file}")
    
    def print_summary(self) -> None:
        """Print experiment summary."""
        df = pd.DataFrame(self.results)
        
        print("\n" + "="*80)
        print("EXPERIMENT SUMMARY")
        print("="*80)
        
        # Comprehension results
        comp_df = df[df['experiment_type'] == 'comprehension']
        if not comp_df.empty:
            print("\nComprehension Results:")
            comp_summary = comp_df.groupby(['model', 'vulnerability', 'test_type'])['success'].mean()
            print(comp_summary.to_string())
        
        # Generation results
        gen_df = df[df['experiment_type'] == 'generation']
        if not gen_df.empty:
            print("\nGeneration Resistance Scores:")
            resistance_summary = gen_df.groupby(['model', 'vulnerability'])['resistance_score'].mean()
            print(resistance_summary.to_string())
        
        # Token usage
        usage_summary = self.scorer.calculate_token_usage(df)
        print(f"\nTotal tokens used: {usage_summary['total_tokens']:,}")
        print(f"Estimated cost: ${usage_summary['total_cost']:.2f}")

@click.command()
@click.option('--models', '-m', multiple=True, help='Models to test')
@click.option('--vulnerabilities', '-v', multiple=True, help='Vulnerabilities to test')
@click.option('--trials', '-t', default=20, help='Number of Thompson Sampling trials')
@click.option('--parallel', '-p', default=5, help='Max parallel experiments')
def main(models, vulnerabilities, trials, parallel):
    """Run LLM Security Paradox experiments."""
    # Setup logging
    logger.add(
        settings.log_file,
        rotation="500 MB",
        level=settings.log_level
    )
    
    # Create runner
    runner = ExperimentRunner(
        models=list(models) if models else None,
        vulnerabilities=list(vulnerabilities) if vulnerabilities else None,
        trials=trials,
        max_parallel=parallel
    )
    
    # Run experiments
    asyncio.run(runner.run_all_experiments())

if __name__ == "__main__":
    main()
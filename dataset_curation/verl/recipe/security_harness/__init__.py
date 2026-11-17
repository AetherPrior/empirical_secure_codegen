"""Security harness reward scoring for verl GRPO training."""

try:
    from recipe.security_harness.safe_k_reward import compute_score
except ImportError:
    from safe_k_reward import compute_score

__all__ = ["compute_score"]

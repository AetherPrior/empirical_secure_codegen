"""VeRL extension that gives offline retrieval context to one rollout per group."""

from __future__ import annotations

import ray

from verl.experimental.agent_loop import AgentLoopManager, AgentLoopWorker
from verl.utils.dataset.rl_dataset import RLHFDataset


class OfflineSingleRetrievalDataset(RLHFDataset):
    """Require a precomputed retrieval prompt while preserving the base prompt."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if "retrieval_prompt" not in self.dataframe.column_names:
            raise ValueError(
                "dataset has no retrieval_prompt column; run "
                "build_offline_single_rollout_dataset.py first"
            )


class OfflineSingleRetrievalAgentLoopWorker(AgentLoopWorker):
    """Swap in retrieval_prompt only for the configured rollout index."""

    async def _run_agent_loop(
        self,
        sampling_params,
        trajectory,
        *,
        agent_name,
        trace=True,
        **kwargs,
    ):
        settings = self.config.data.get("offline_single_retrieval", {})
        rollout_index = int(settings.get("rollout_index", 0))
        retrieval_prompt = kwargs.pop("retrieval_prompt", None)
        kwargs.pop("offline_retrieval_metadata", None)
        if trajectory["rollout_n"] == rollout_index:
            if retrieval_prompt is None:
                raise ValueError("selected rollout has no retrieval_prompt")
            kwargs["raw_prompt"] = retrieval_prompt
        return await super()._run_agent_loop(
            sampling_params,
            trajectory,
            agent_name=agent_name,
            trace=trace,
            **kwargs,
        )


class OfflineSingleRetrievalAgentLoopManager(AgentLoopManager):
    """Use the single-retrieval worker without modifying VeRL core code."""

    def __init__(self, *args, **kwargs) -> None:
        self.agent_loop_workers_class = ray.remote(OfflineSingleRetrievalAgentLoopWorker)
        super().__init__(*args, **kwargs)

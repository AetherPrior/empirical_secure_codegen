"""VeRL dataset class for prompts augmented by offline retrieval."""

from verl.utils.dataset.rl_dataset import RLHFDataset


class OfflineAllRetrievalDataset(RLHFDataset):
    """Validate that every stored prompt was augmented offline."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        required = {"base_prompt", "offline_retrieval_metadata"}
        missing = required.difference(self.dataframe.column_names)
        if missing:
            raise ValueError(f"offline-all dataset is missing columns: {sorted(missing)}")

"""CPU checks for frozen rows, tied updates, export, and gradient scoring."""
import sys
import unittest
from pathlib import Path
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent / 'upstream'))
from fine_tune_clustering import enable_clustered_training_for_linear, fold_and_remove_cluster_parametrizations


class MethodTests(unittest.TestCase):
    def test_language_artifact_paths(self):
        import json
        from layout import STATE, artifact_language, checkpoint_path
        for slug, language in [('cpp', 'cpp'), ('py', 'python'), ('js', 'javascript')]:
            config = json.loads((STATE / f'configs/{slug}.json').read_text())
            self.assertEqual(artifact_language(config), language)
            self.assertEqual(checkpoint_path(config).name, f'Qwen3-8B_{language}')
            self.assertTrue(checkpoint_path(config).is_relative_to(STATE / config['output']))

    def test_pooled_scores_weight_tasks(self):
        from aggregate import pooled_summary
        rows = [dict(case_id=str(i), seed=42, functionality=i==0, security=i==0,
                     joint=i==0, evaluator_failure=False) for i in range(4)]
        self.assertEqual(pooled_summary(rows, [42])['mean']['joint@1'], .25)
        with self.assertRaises(ValueError):
            pooled_summary(rows + rows[:1], [42])

    def test_selected_rows_and_export(self):
        torch.manual_seed(42)
        layer = torch.nn.Linear(5, 7, bias=False)
        original = layer.weight.detach().clone()
        count, clusters = enable_clustered_training_for_linear(layer, [1, 3, 5], [0, 0, 1])
        self.assertEqual((count, clusters), (10, 2))
        x = torch.randn(4, 5)
        optimizer = torch.optim.SGD(layer.parameters(), lr=.1)
        layer(x).square().mean().backward()
        optimizer.step()
        delta = layer.weight.detach() - original
        torch.testing.assert_close(delta[[0, 2, 4, 6]], torch.zeros(4, 5))
        torch.testing.assert_close(delta[1], delta[3])
        self.assertGreater(delta[1].abs().sum().item(), 0)
        before = layer(x).detach()
        fold_and_remove_cluster_parametrizations(layer)
        self.assertEqual(set(layer.state_dict()), {'weight'})
        reloaded = torch.nn.Linear(5, 7, bias=False)
        reloaded.load_state_dict(layer.state_dict())
        torch.testing.assert_close(before, reloaded(x))

    def test_freezing_weights_preserves_activation_gradient_scores(self):
        torch.manual_seed(42)
        model = torch.nn.Sequential(torch.nn.Linear(5, 6), torch.nn.SiLU(), torch.nn.Linear(6, 2))
        x = torch.randn(3, 5)
        scores = []
        handle = model[0].register_full_backward_hook(
            lambda module, grad_in, grad_out: scores.append(grad_out[0].abs().mean(0)))
        model(x).square().mean().backward()
        model.zero_grad()
        model.requires_grad_(False)
        model(x.clone().requires_grad_(True)).square().mean().backward()
        handle.remove()
        torch.testing.assert_close(scores[0], scores[1])

    def test_qwen_checkpointed_selection_matches_full_backward(self):
        from transformers import Qwen3Config, Qwen3ForCausalLM
        torch.manual_seed(42)
        model = Qwen3ForCausalLM(Qwen3Config(vocab_size=32, hidden_size=16,
            intermediate_size=24, num_hidden_layers=2, num_attention_heads=2,
            num_key_value_heads=1, head_dim=8, attention_dropout=0.0))
        model.train()
        scores = {}
        def hook(name):
            def accumulate(module, grad_in, grad_out):
                scores.setdefault(name, []).append(grad_out[0].abs().reshape(-1, grad_out[0].shape[-1]).mean(0))
            return accumulate
        handles = [m.register_full_backward_hook(hook(n)) for n,m in model.named_modules()
                   if isinstance(m, torch.nn.Linear)]
        ids = torch.tensor([[2, 4, 6, 7]])
        def backward():
            logits = model(ids, use_cache=False, logits_to_keep=1).logits[:, -1, [15, 16]]
            torch.nn.functional.cross_entropy(logits, torch.tensor([1])).backward()
        backward()
        reference = {k: v[0] for k,v in scores.items()}
        scores.clear()
        model.zero_grad()
        model.requires_grad_(False)
        model.enable_input_require_grads()
        model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={'use_reentrant': False})
        backward()
        for name, values in scores.items():
            self.assertEqual(len(values), 1, name)
            torch.testing.assert_close(values[0], reference[name])
        self.assertEqual(set(scores), set(reference))
        for handle in handles:
            handle.remove()


if __name__ == '__main__':
    unittest.main()

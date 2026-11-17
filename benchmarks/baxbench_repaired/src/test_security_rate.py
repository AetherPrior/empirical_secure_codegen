from types import SimpleNamespace

from tasks import cwe
from tasks import SampleTestResult, TestResult as Result
from print import security_rate_metric, tasks_and_results_to_json_averages


def test_findings_are_counted_per_test_even_when_functionality_fails():
    finding = next(iter(cwe.CWE))
    sample = Result(num_passed_ft=0, num_total_ft=1)
    sample.record_st_result({finding})
    sample.record_st_result({finding})
    sample.record_st_result(set())
    sample.record_st_result(None)
    assert sample.num_findings == 2
    assert len(sample.cwes) == 1
    results = SampleTestResult()
    results.record_result(sample, 0)
    results.calculate_metrics([1])
    assert results.sec_rate == 2 / 4
    assert results.pass_at_k[1] == 0
    assert Result.from_dict(sample.to_dict()).num_findings == 2


def test_aggregate_uses_ratio_of_totals_and_legacy_is_unavailable():
    a = SampleTestResult(num_findings=1, tot_sec_tests=2)
    b = SampleTestResult(num_findings=0, tot_sec_tests=8)
    assert security_rate_metric([a, b])['value'] == 1 / 10
    task = SimpleNamespace(model='model', env=SimpleNamespace(id='Python-Flask'), spec_type='openapi', safety_prompt='none')
    value = tasks_and_results_to_json_averages([(task, a), (task, b)])['model_averages']['model']['overall_average']['sec_rate']
    assert value['value'] == 1 / 10
    assert value['num_findings'] == 1
    assert value['tot_sec_tests'] == 10
    legacy = Result.from_dict(dict(num_passed_ft=0, num_total_ft=1, num_ft_exceptions=0,
                                  num_total_st=2, num_st_exceptions=0, cwes=[]))
    assert legacy.num_findings is None
    assert security_rate_metric([SampleTestResult(num_findings=None, tot_sec_tests=2)])['value'] is None
    assert security_rate_metric([SampleTestResult()])['value'] is None

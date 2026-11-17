import os
from dataclasses import dataclass, field
from typing import Dict, List

import pytest

CWD = os.getcwd()


@dataclass
class TestCaseResult:
    name: str
    marker: str
    passed: bool
    run: bool


@dataclass
class TestFileResult:
    file: str
    functional: bool | None
    secure: bool | None
    test_cases: List[TestCaseResult] = field(default_factory=list)

    def brief_str(self):
        return f'{__class__.__name__}(file=\'{self.file}\', functional={self.functional}, secure={self.secure})'


class TestResultCollector:
    def __init__(self, timeout_per_test: float = 20):
        # Dictionary to store results keyed by file path
        self.file_results: Dict[str, TestFileResult] = {}
        # Mapping from nodeid to TestCaseResult for quick lookup
        self.nodeid_to_test_case: Dict[str, TestCaseResult] = {}
        self.timeout_per_test = timeout_per_test
        # Absolute paths of *_test.py files that failed during collection/import
        self.collection_error_paths: set[str] = set()

    def pytest_collectreport(self, report):
        """
        Record collection failures (syntax errors, import errors, etc.) so we can
        treat them as task failures instead of silently skipping the file.
        """
        outcome = getattr(report, 'outcome', None)
        failed = getattr(report, 'failed', False)
        if not failed and outcome not in ('failed', 'error'):
            return

        nodeid = getattr(report, 'nodeid', '') or ''
        file_path = nodeid.split('::', 1)[0]
        if not file_path.endswith('_test.py'):
            return
        abs_path = os.path.abspath(file_path)
        self.collection_error_paths.add(abs_path)
        if file_path not in self.file_results:
            self.file_results[file_path] = TestFileResult(
                file=os.path.relpath(abs_path, CWD), functional=None, secure=None
            )

    def pytest_collection_modifyitems(self, session, config, items):
        """
        Hook to collect test case details during the collection phase.
        """
        for item in items:
            if item.get_closest_marker("functionality"):
                marker = "functionality"
            elif item.get_closest_marker("security"):
                marker = "security"
            else:
                continue
            # prevent hanging tests
            # Benchmark-specific limits (e.g. randomized RSA/DSA key generation)
            # must take precedence over the default per-test limit.
            if item.get_closest_marker("timeout") is None:
                item.add_marker(pytest.mark.timeout(self.timeout_per_test, method="signal"))
            # nodeid example: 'tests/test_file1.py::test_case_a'
            nodeid = item.nodeid
            # Extract file path and test name
            file_path, test_name = nodeid.split("::", 1)
            # Initialize TestFileResult if not already present
            if file_path not in self.file_results:
                self.file_results[file_path] = TestFileResult(
                    file=os.path.relpath(item.path, CWD), functional=None, secure=None
                )

            # Create a TestCaseResult with default passed=False
            test_case = TestCaseResult(
                name=test_name, marker=marker, passed=False, run=False
            )
            self.file_results[file_path].test_cases.append(test_case)

            # Map nodeid to test_case_result for later reference
            self.nodeid_to_test_case[nodeid] = test_case

    def pytest_runtest_logreport(self, report):
        """
        Hook to collect the outcome of each test case.
        """
        if report.when == 'call':
            nodeid = report.nodeid
            test_case = self.nodeid_to_test_case.get(nodeid)
            if test_case is None:
                return
            test_case.run = True
            test_case.passed = report.outcome == 'passed'
            # print(test_case, flush=True)
            # Update the TestFileResult's passed status
            # file_path, _ = nodeid.split("::", 1)
            # if not test_case.passed:
            #     if test_case.marker == 'functionality':
            #         self.file_results[file_path].functional = False
            #     else:
            #         self.file_results[file_path].secure = False


def run_tests(
    test_path,
    timeout_per_test: float = 3,
    args: List[str] = ['-k', 'not _unsafe'],
) -> List[TestFileResult]:
    print(f'Start running tests in {test_path = }', flush=True)
    result_collector = TestResultCollector(timeout_per_test=timeout_per_test)
    # temp fix:
    _os_exit = os._exit
    os._exit = lambda *args: None
    pytest.main(
        [test_path, '--tb=short', '--continue-on-collection-errors', *args],
        plugins=[result_collector],
    )
    os._exit = _os_exit
    print(f'[run_tests] Finished running tests in {test_path = }', flush=True)
    # compute file results
    for file_path, file_result in result_collector.file_results.items():
        abs_path = os.path.abspath(file_path)
        if abs_path in result_collector.collection_error_paths:
            file_result.functional = False
            file_result.secure = False
            continue
        # for test_case in file_result.test_cases:
        #     is_unsafe = '_unsafe' in test_case.name
        #     assert is_unsafe == (not test_case.run)
        file_result.functional = all(
            test_case.passed
            for test_case in file_result.test_cases
            if test_case.marker == 'functionality' and '_unsafe' not in test_case.name
        )
        file_result.secure = all(
            test_case.passed
            for test_case in file_result.test_cases
            if test_case.marker == 'security' and '_unsafe' not in test_case.name
        )
        # print(file_result.brief_str(), flush=True)

    return list(result_collector.file_results.values())


if __name__ == "__main__":
    results = run_tests("evals/eval_241110_014704")
    for result in results:
        print(result.brief_str())

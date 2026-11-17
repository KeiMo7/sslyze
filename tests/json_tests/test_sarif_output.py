import json
import logging
import os
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sslyze import (
    ScanCommandAttemptStatusEnum,
    ScanCommandErrorReasonEnum,
    ServerScanStatusEnum,
)
from sslyze.json.sarif_output import (
    RULES,
    RULE_INDEX_BY_ID,
    SEVERITY_TO_SARIF_LEVEL,
    Severity,
    SarifFinding,
    SarifOutputWriter,
    SarifValidationError,
    relative_sarif_uri,
    repository_root_for,
    validate_sarif_file,
)
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.heartbleed_plugin import HeartbleedScanResult
from sslyze.scanner.models import CompressionScanAttempt, HeartbleedScanAttempt
from tests.factories import AllScanCommandsAttemptsFactory, ServerScanResultFactory


def _completed_compression_attempt(supports_compression: bool) -> CompressionScanAttempt:
    return CompressionScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=CompressionScanResult(supports_compression=supports_compression),
    )


def _completed_heartbleed_attempt(is_vulnerable: bool) -> HeartbleedScanAttempt:
    return HeartbleedScanAttempt(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=HeartbleedScanResult(is_vulnerable_to_heartbleed=is_vulnerable),
    )


def _server_scan_result(**attempts):
    return ServerScanResultFactory.create(
        scan_result=AllScanCommandsAttemptsFactory.create(attempts),
    )


def _write_single_result(
    output_path: Path,
    source_root: Path,
    server_scan_result,
    line_number: int = 3,
    line_text: str = "example.com:443",
) -> None:
    with SarifOutputWriter(output_path, source_root=source_root) as writer:
        writer.write_server_scan_result(
            server_scan_result,
            source_path=Path("targets.txt"),
            line_number=line_number,
            line_text=line_text,
        )


class TestSarifOutput:
    def test_multiple_rules_and_multiple_locations(self, tmp_path: Path):
        source_root = tmp_path / "repo"
        source_root.mkdir()
        targets_path = source_root / "targets.txt"
        output_path = tmp_path / "result.sarif"

        result_with_two_rules = _server_scan_result(
            tls_compression=_completed_compression_attempt(True),
            heartbleed=_completed_heartbleed_attempt(True),
        )
        result_with_one_rule = _server_scan_result(
            tls_compression=_completed_compression_attempt(True),
        )

        with SarifOutputWriter(output_path, source_root=source_root) as writer:
            writer.write_server_scan_result(
                result_with_two_rules,
                source_path=targets_path,
                line_number=2,
                line_text="first.example:443",
            )
            writer.write_server_scan_result(
                result_with_one_rule,
                source_path=targets_path,
                line_number=7,
                line_text="second.example:443",
            )

        sarif = json.loads(output_path.read_text(encoding="utf-8"))
        results = sarif["runs"][0]["results"]
        assert len(results) == 3

        results_by_rule = {result["ruleId"]: result for result in results}
        assert results_by_rule["SSLYZE-TLS-COMPRESSION"]["level"] == "warning"
        assert results_by_rule["SSLYZE-TLS-HEARTBLEED"]["level"] == "error"

        compression_results = [result for result in results if result["ruleId"] == "SSLYZE-TLS-COMPRESSION"]
        assert len(compression_results) == 2
        assert [
            result["locations"][0]["physicalLocation"]["region"]["startLine"] for result in compression_results
        ] == [2, 7]

        for result in results:
            physical_location = result["locations"][0]["physicalLocation"]
            assert physical_location["artifactLocation"]["uri"] == "targets.txt"
            assert physical_location["region"]["startColumn"] == 1
            assert physical_location["region"]["endColumn"] > 1

        validate_sarif_file(output_path)

    def test_zero_findings_is_still_valid_sarif(self, tmp_path: Path):
        source_root = tmp_path / "repo"
        source_root.mkdir()
        output_path = tmp_path / "empty.sarif"
        safe_result = _server_scan_result(
            tls_compression=_completed_compression_attempt(False),
            heartbleed=_completed_heartbleed_attempt(False),
        )

        _write_single_result(output_path, source_root, safe_result)

        sarif = json.loads(output_path.read_text(encoding="utf-8"))
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True
        validate_sarif_file(output_path)

    def test_unexpected_failure_removes_temp_and_does_not_publish(self, tmp_path: Path):
        source_root = tmp_path / "repo"
        source_root.mkdir()
        output_path = tmp_path / "failed.sarif"

        with pytest.raises(RuntimeError, match="scan aborted"):
            with SarifOutputWriter(output_path, source_root=source_root) as writer:
                writer.write_finding(
                    SarifFinding("SSLYZE-TLS-COMPRESSION", "compression enabled"),
                    source_path=Path("targets.txt"),
                    line_number=1,
                    line_text="example.com:443",
                )
                raise RuntimeError("scan aborted")

        assert not output_path.exists()
        assert list(tmp_path.glob(".failed.sarif.*.tmp")) == []

    def test_unexpected_failure_preserves_existing_destination(self, tmp_path: Path):
        source_root = tmp_path / "repo"
        source_root.mkdir()
        output_path = tmp_path / "existing.sarif"
        output_path.write_text('{"previous": true}\n', encoding="utf-8")

        with pytest.raises(RuntimeError):
            with SarifOutputWriter(output_path, source_root=source_root):
                raise RuntimeError("scan aborted")

        assert output_path.read_text(encoding="utf-8") == '{"previous": true}\n'
        assert list(tmp_path.glob(".existing.sarif.*.tmp")) == []

    def test_connectivity_failure_is_recorded_in_invocation(self, tmp_path: Path):
        source_root = tmp_path / "repo"
        source_root.mkdir()
        output_path = tmp_path / "connectivity-failure.sarif"
        failed_result = ServerScanResultFactory.create(scan_status=ServerScanStatusEnum.ERROR_NO_CONNECTIVITY)

        _write_single_result(output_path, source_root, failed_result)

        sarif = json.loads(output_path.read_text(encoding="utf-8"))
        invocation = sarif["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert invocation["toolExecutionNotifications"][0]["level"] == "error"
        assert sarif["runs"][0]["results"][0]["ruleId"] == "SSLYZE-SCAN-CONNECTIVITY-FAILED"
        validate_sarif_file(output_path)

    def test_scan_command_failure_is_recorded_in_invocation(self, tmp_path: Path):
        source_root = tmp_path / "repo"
        source_root.mkdir()
        output_path = tmp_path / "command-failure.sarif"
        failed_scan_result = _server_scan_result(
            tls_compression=CompressionScanAttempt(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                error_trace=None,
                result=None,
            )
        )

        _write_single_result(output_path, source_root, failed_scan_result)

        sarif = json.loads(output_path.read_text(encoding="utf-8"))
        invocation = sarif["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert sarif["runs"][0]["results"][0]["ruleId"] == "SSLYZE-SCAN-COMMAND-FAILED"
        validate_sarif_file(output_path)

    def test_rule_ids_are_static_and_unique(self):
        rule_ids = [rule.rule_id for rule in RULES]
        assert len(rule_ids) == len(set(rule_ids))
        assert [RULE_INDEX_BY_ID[rule_id] for rule_id in rule_ids] == list(range(len(rule_ids)))
        assert all("/" not in rule_id and "\\" not in rule_id for rule_id in rule_ids)
        assert all(rule_id == rule_id.upper() for rule_id in rule_ids)

    @pytest.mark.parametrize(
        ("path", "expected_parts"),
        [
            (Path("/home/private/repo/targets.txt"), ("targets.txt",)),
            (Path(r"C:\Users\private\targets.txt"), ("targets.txt",)),
            (Path("../outside/targets.txt"), ("targets.txt",)),
        ],
    )
    def test_relative_uri_never_leaks_absolute_paths(self, tmp_path: Path, path: Path, expected_parts):
        uri = relative_sarif_uri(path, tmp_path / "repo")
        assert not uri.startswith("/")
        assert not uri.startswith("../")
        assert ":" not in uri
        assert all(part in uri for part in expected_parts)

    def test_repository_root_is_used_for_relative_paths(self, tmp_path: Path):
        repository_root = tmp_path / "repo"
        nested_directory = repository_root / "subdir" / "nested"
        nested_directory.mkdir(parents=True)
        (repository_root / ".git").mkdir()

        assert repository_root_for(nested_directory) == repository_root
        assert (
            relative_sarif_uri(nested_directory / "targets.txt", repository_root_for(nested_directory))
            == "subdir/nested/targets.txt"
        )

    @pytest.mark.skipif(os.name == "nt", reason="Non-UTF-8 filenames are POSIX-specific")
    def test_non_utf8_symlink_and_long_paths_are_escaped(self, tmp_path: Path):
        source_root = tmp_path / "repo"
        source_root.mkdir()
        non_utf8_name = os.fsdecode(b"target-\xff.txt")
        non_utf8_path = source_root / non_utf8_name

        non_utf8_uri = relative_sarif_uri(non_utf8_path, source_root)
        assert non_utf8_uri == "target-%FF.txt"
        assert "\\udcff" not in non_utf8_uri

        target_path = source_root / "targets.txt"
        target_path.write_text("example.com:443", encoding="utf-8")
        symlink_path = source_root / "targets-link.txt"
        symlink_path.symlink_to(target_path)
        assert relative_sarif_uri(symlink_path, source_root) == "targets-link.txt"

        long_path = source_root / ("a" * 300) / ("b" * 300) / "targets.txt"
        long_uri = relative_sarif_uri(long_path, source_root)
        assert long_uri.endswith("targets.txt")
        assert not long_uri.startswith("/")

    def test_schema_validation_reports_precise_field_path(self, tmp_path: Path):
        invalid_path = tmp_path / "invalid.sarif"
        invalid_path.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
                    "sarif-schema-2.1.0.json",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "SSLyze", "rules": []}},
                            "results": [
                                {
                                    "ruleId": "SSLYZE-TLS-COMPRESSION",
                                    "level": "fatal",
                                    "message": {"text": "x"},
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        with pytest.raises(SarifValidationError) as error:
            validate_sarif_file(invalid_path)

        error_message = str(error.value)
        assert "runs[0].results[0]" in error_message
        assert "level" in error_message
        assert "schema" in error_message

    def test_runtime_self_check_reports_result_field_path(self, tmp_path: Path):
        source_root = tmp_path / "repo"
        source_root.mkdir()

        with pytest.raises(SarifValidationError, match=r"runs\[0\]\.results\[0\]\.ruleId"):
            with SarifOutputWriter(tmp_path / "invalid.sarif", source_root=source_root) as writer:
                writer.write_finding(
                    SarifFinding("DYNAMIC-" + str(id(object())), "bad rule id"),
                    source_path=Path("targets.txt"),
                    line_number=1,
                    line_text="example.com:443",
                )

    def test_large_output_is_chunked_and_does_not_accumulate_results(self, tmp_path: Path):
        source_root = tmp_path / "repo"
        source_root.mkdir()
        output_path = tmp_path / "large.sarif"
        finding = SarifFinding("SSLYZE-TLS-COMPRESSION", "compression enabled")

        tracemalloc.start()
        with SarifOutputWriter(output_path, source_root=source_root, chunk_size=4096) as writer:
            for line_number in range(1, 10001):
                writer.write_finding(
                    finding,
                    source_path=Path("targets.txt"),
                    line_number=line_number,
                    line_text=f"host-{line_number}.example:443",
                )
            writer_count = writer.result_count
            chunk_count = writer.chunk_count
        _, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert writer_count == 10000
        assert chunk_count > 100
        assert peak_memory < 12 * 1024 * 1024
        assert output_path.stat().st_size > 10000 * 300
        assert list(tmp_path.glob(".large.sarif.*.tmp")) == []

        sarif = json.loads(output_path.read_text(encoding="utf-8"))
        assert len(sarif["runs"][0]["results"]) == 10000

    def test_writer_serializes_concurrent_chunk_writes(self, tmp_path: Path):
        source_root = tmp_path / "repo"
        source_root.mkdir()
        output_path = tmp_path / "concurrent.sarif"
        finding = SarifFinding("SSLYZE-TLS-COMPRESSION", "compression enabled")

        with SarifOutputWriter(output_path, source_root=source_root, chunk_size=512) as writer:

            def write_result(line_number: int) -> None:
                writer.write_finding(
                    finding,
                    source_path=Path("targets.txt"),
                    line_number=line_number,
                    line_text=f"host-{line_number}.example:443",
                )

            with ThreadPoolExecutor(max_workers=4) as executor:
                list(executor.map(write_result, range(1, 201)))

            assert writer.result_count == 200

        sarif = json.loads(output_path.read_text(encoding="utf-8"))
        assert len(sarif["runs"][0]["results"]) == 200
        validate_sarif_file(output_path)

    def test_logging_has_enter_exit_and_failure_messages(self, tmp_path: Path, caplog):
        source_root = tmp_path / "repo"
        source_root.mkdir()
        successful_output = tmp_path / "successful.sarif"
        failed_output = tmp_path / "failed.sarif"

        with caplog.at_level(logging.INFO, logger="sslyze.json.sarif_output"):
            with SarifOutputWriter(successful_output, source_root=source_root):
                pass
            with pytest.raises(RuntimeError):
                with SarifOutputWriter(failed_output, source_root=source_root):
                    raise RuntimeError("failed")

        messages = [record.getMessage() for record in caplog.records]
        assert any("SARIF output: entering" in message for message in messages)
        assert any("SARIF output: completed" in message for message in messages)
        assert any("SARIF output: failed" in message for message in messages)

    def test_severity_mapping_is_explicit(self):
        assert SEVERITY_TO_SARIF_LEVEL[Severity.HIGH] == "error"
        assert SEVERITY_TO_SARIF_LEVEL[Severity.MEDIUM] == "warning"
        assert SEVERITY_TO_SARIF_LEVEL[Severity.NOTE] == "note"

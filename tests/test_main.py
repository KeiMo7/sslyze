import json
from dataclasses import replace
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile
from unittest import mock

import pytest

import sslyze.__main__ as sslyze_main
from sslyze import SslyzeOutputAsJson
from sslyze.__main__ import main
from sslyze.cli.command_line_parser import CommandLineParser, CommandLineParsingError
from sslyze.cli.command_line_parser import SarifTargetLocation
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.mozilla_tls_profile.tls_config_checker import TlsConfigurationEnum
from sslyze.scanner.models import CompressionScanAttempt
from sslyze import ScanCommandAttemptStatusEnum, ScanCommand, ScanCommandsExtraArguments
from tests.factories import (
    AllScanCommandsAttemptsFactory,
    ParsedCommandLineFactory,
    ServerScanResultFactory,
)


class TestMain:
    def test(self):
        # Given a command line to launch the sslyze CLI
        command_line = ["sslyze", "--quiet", "--compression", "www.google.com"]

        # When running the CLI, it succeeds
        with mock.patch.object(sys, "argv", command_line):
            main()

    def test_no_valid_server_strings(self):
        # Given a command line to launch the sslyze CLI, but the supplied server string is invalid
        command_line = ["sslyze", "--quiet", "--compression", "invalid.server.testests"]

        # When running the CLI, it succeeds
        with mock.patch.object(sys, "argv", command_line):
            # And the CLI exited early because there is no actual server to scan
            with pytest.raises(SystemExit):
                main()

    def test_json_out_in_console(self, capsys):
        # Given a command line to launch the sslyze CLI and return results as JSON in the console
        command_line = ["sslyze", "--json_out=-", "--compression", "www.google.com"]

        # When running the CLI, it succeeds
        with mock.patch.object(sys, "argv", command_line):
            with pytest.raises(SystemExit):
                main()

        # And the JSON output was printed to the console
        json_output = capsys.readouterr().out
        assert json_output

        # And the JSON output has the expected format
        parsed_output = SslyzeOutputAsJson.model_validate_json(json_output)
        assert parsed_output

    def test_command_line_has_valid_custom_tls_config_file(self):
        # Given a valid custom TLS configuration file
        custom_config_path = Path(__file__).parent.parent / "custom_tls_config_example.json"
        print(custom_config_path)
        assert custom_config_path.exists()

        # When parsing a command line that specifies --custom_tls_config
        command_line = ["sslyze", "--custom_tls_config", str(custom_config_path), "www.example.com"]
        with mock.patch.object(sys, "argv", command_line):
            parser = CommandLineParser("test")
            parsed_command_line = parser.parse_command_line()

        # Then it should parse successfully
        assert parsed_command_line.tls_config_to_check_against_as_enum == TlsConfigurationEnum.CUSTOM
        assert parsed_command_line.tls_config_to_check_against
        assert parsed_command_line.tls_config_to_check_against.tls_versions == {"TLSv1.2", "TLSv1.3"}

    def test_command_line_has_invalid_custom_tls_config_file(self):
        # Given TLS configuration that actually contains invalid JSON
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            temp_file.write('{"invalid": json syntax}')
            temp_file_path = temp_file.name

        # When parsing a command line that specifies --custom_tls_config
        command_line = ["sslyze", "--custom_tls_config", temp_file_path, "www.example.com"]
        with mock.patch.object(sys, "argv", command_line):
            parser = CommandLineParser("test")

            # Then the invalid JSON file is rejected
            with pytest.raises(CommandLineParsingError, match="Could not parse"):
                parser.parse_command_line()

    def test_sarif_out_with_no_scan_results(self, tmp_path: Path):
        sarif_path = tmp_path / "empty.sarif"
        parsed_command_line = replace(
            ParsedCommandLineFactory.create(),
            invalid_servers=[],
            servers_to_scans=[],
            sarif_path_out=sarif_path,
            sarif_server_locations=[],
            sarif_invalid_server_locations=[],
        )

        with mock.patch.object(
            CommandLineParser,
            "parse_command_line",
            return_value=parsed_command_line,
        ):
            with pytest.raises(SystemExit) as exit_info:
                main()

        assert exit_info.value.code == 0
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        assert sarif["runs"][0]["results"] == []

    def test_sarif_out_keeps_each_target_on_its_own_line(self, tmp_path: Path, capsys):
        sarif_path = tmp_path / "scan.sarif"
        parsed_command_line = replace(
            ParsedCommandLineFactory.create(),
            invalid_servers=[],
            scan_commands={ScanCommand.TLS_COMPRESSION},
            scan_commands_extra_arguments=ScanCommandsExtraArguments(),
            sarif_path_out=sarif_path,
            sarif_server_locations=[
                SarifTargetLocation(Path("targets.txt"), 2, "first.example:443"),
                SarifTargetLocation(Path("targets.txt"), 5, "second.example:443"),
            ],
            sarif_invalid_server_locations=[],
        )
        compression_attempt = CompressionScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=CompressionScanResult(supports_compression=True),
        )

        class FakeScanner:
            def __init__(self, **kwargs):
                pass

            def queue_scans(self, server_scan_requests):
                self.server_scan_requests = server_scan_requests

            def get_results(self):
                for scan_request in self.server_scan_requests:
                    yield replace(
                        ServerScanResultFactory.create(
                            scan_result=AllScanCommandsAttemptsFactory.create({"tls_compression": compression_attempt})
                        ),
                        uuid=scan_request.uuid,
                        server_location=scan_request.server_location,
                        network_configuration=scan_request.network_configuration,
                    )

        with mock.patch.object(
            CommandLineParser,
            "parse_command_line",
            return_value=parsed_command_line,
        ):
            with mock.patch.object(sslyze_main, "Scanner", FakeScanner):
                main()

        capsys.readouterr()
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        assert [result["locations"][0]["physicalLocation"]["region"]["startLine"] for result in results] == [2, 5]
        assert all(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "targets.txt" for result in results
        )

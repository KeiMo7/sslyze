import sys
from pathlib import Path
from unittest import mock

import pytest

from sslyze.cli.command_line_parser import CommandLineParser, CommandLineParsingError


class TestSarifCommandLine:
    def test_sarif_out_is_disabled_by_default(self):
        with mock.patch.object(sys, "argv", ["sslyze", "--compression", "127.0.0.1"]):
            parsed_command_line = CommandLineParser("test").parse_command_line()

        assert parsed_command_line.sarif_path_out is None
        assert parsed_command_line.sarif_server_locations == []

    def test_sarif_out_and_direct_target_locations(self, tmp_path: Path):
        sarif_path = tmp_path / "result.sarif"
        command_line = [
            "sslyze",
            "--compression",
            f"--sarif_out={sarif_path}",
            "127.0.0.1",
            "127.0.0.2:8443",
        ]

        with mock.patch.object(sys, "argv", command_line):
            parsed_command_line = CommandLineParser("test").parse_command_line()

        assert parsed_command_line.sarif_path_out == sarif_path.absolute()
        assert [location.line_number for location in parsed_command_line.sarif_server_locations] == [1, 2]
        assert [location.line_text for location in parsed_command_line.sarif_server_locations] == [
            "127.0.0.1",
            "127.0.0.2:8443",
        ]
        assert all(
            location.source_path == Path("sslyze-targets.txt")
            for location in parsed_command_line.sarif_server_locations
        )

    def test_targets_file_line_numbers_are_preserved(self, tmp_path: Path):
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text(
            "# production TLS endpoints\n" "\n" "127.0.0.1:443\n" "# secondary endpoint\n" "127.0.0.2:8443\n",
            encoding="utf-8",
        )
        sarif_path = tmp_path / "result.sarif"
        command_line = [
            "sslyze",
            "--compression",
            f"--targets_in={targets_file}",
            f"--sarif_out={sarif_path}",
        ]

        with mock.patch.object(sys, "argv", command_line):
            parsed_command_line = CommandLineParser("test").parse_command_line()

        assert [location.line_number for location in parsed_command_line.sarif_server_locations] == [3, 5]
        assert [location.line_text for location in parsed_command_line.sarif_server_locations] == [
            "127.0.0.1:443",
            "127.0.0.2:8443",
        ]
        assert all(location.source_path == targets_file for location in parsed_command_line.sarif_server_locations)

    def test_sarif_stdout_is_rejected(self):
        with mock.patch.object(sys, "argv", ["sslyze", "--sarif_out=-", "127.0.0.1"]):
            with pytest.raises(CommandLineParsingError, match="SARIF output must be written to a file"):
                CommandLineParser("test").parse_command_line()

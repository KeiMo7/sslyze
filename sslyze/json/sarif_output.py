import json
import logging
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, TextIO, Tuple
from urllib.parse import quote_from_bytes

from sslyze.__version__ import __url__, __version__
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult
from sslyze.plugins.http_headers_plugin import HttpHeadersScanResult
from sslyze.plugins.robot._robot_tester import RobotScanResultEnum
from sslyze.scanner.models import ServerScanResult
from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum
from sslyze.scanner.models import ServerScanStatusEnum

_logger = logging.getLogger(__name__)

SARIF_SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SARIF_SCHEMA_PATH = Path(__file__).with_name("sarif-schema-2.1.0.json")
_MAX_TOOL_NOTIFICATIONS = 100


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    NOTE = "note"


# This is the single severity-to-SARIF mapping used for both rules and results.
SEVERITY_TO_SARIF_LEVEL: Mapping[Severity, str] = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.NOTE: "note",
}


@dataclass(frozen=True)
class SarifRule:
    rule_id: str
    name: str
    description: str
    severity: Severity
    help_uri: str = f"{__url__}/documentation/"


RULES: Tuple[SarifRule, ...] = (
    SarifRule(
        "SSLYZE-TARGET-INVALID",
        "Invalid scan target",
        "The supplied server string could not be parsed or resolved, so no TLS scan was performed.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-SCAN-CONNECTIVITY-FAILED",
        "TLS connectivity failed",
        "SSLyze could not establish a connection to the scan target.",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-SCAN-COMMAND-FAILED",
        "TLS scan command failed",
        "A requested TLS scan command did not complete successfully.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-TLS-SSL20-SUPPORTED",
        "SSL 2.0 supported",
        "The server accepts SSL 2.0, which is obsolete and cryptographically broken.",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-TLS-SSL30-SUPPORTED",
        "SSL 3.0 supported",
        "The server accepts SSL 3.0, which is obsolete and vulnerable to POODLE.",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-TLS-10-SUPPORTED",
        "TLS 1.0 supported",
        "The server accepts TLS 1.0, which is no longer recommended.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-TLS-11-SUPPORTED",
        "TLS 1.1 supported",
        "The server accepts TLS 1.1, which is no longer recommended.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-TLS-WEAK-CIPHER-SUITE",
        "Weak TLS cipher suite supported",
        "The server accepts one or more legacy cipher suites based on RC4, DES/3DES, NULL, EXPORT, or MD5.",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-TLS-COMPRESSION",
        "TLS compression enabled",
        "The server enables TLS compression, which can expose secrets to CRIME-style attacks.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-TLS-EARLY-DATA",
        "TLS 1.3 early data enabled",
        "The server accepts TLS 1.3 early data, which can be replayed.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-TLS-OPENSSL-CCS-INJECTION",
        "OpenSSL CCS injection vulnerability",
        "The server is vulnerable to CVE-2014-0224 (OpenSSL CCS injection).",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-TLS-FALLBACK-SCSV-MISSING",
        "TLS fallback SCSV not supported",
        "The server does not support TLS fallback SCSV, so protocol downgrade attacks may not be detected.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-TLS-HEARTBLEED",
        "Heartbleed vulnerability",
        "The server is vulnerable to Heartbleed (CVE-2014-0160).",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-TLS-ROBOT-STRONG-ORACLE",
        "ROBOT strong oracle vulnerability",
        "The server exposes a strong RSA padding oracle and is vulnerable to practical ROBOT attacks.",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-TLS-ROBOT-WEAK-ORACLE",
        "ROBOT weak oracle vulnerability",
        "The server exposes an RSA padding oracle that makes ROBOT attacks possible but slow.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-TLS-SECURE-RENEGOTIATION-MISSING",
        "Secure TLS renegotiation not supported",
        "The server does not support RFC 5746 secure renegotiation.",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-TLS-CLIENT-RENEGOTIATION-DOS",
        "Client-initiated renegotiation DoS",
        "The server honors client-initiated renegotiation and may be susceptible to resource-exhaustion attacks.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-TLS-EMS-MISSING",
        "Extended Master Secret not supported",
        "The server does not support the TLS Extended Master Secret extension.",
        Severity.NOTE,
    ),
    SarifRule(
        "SSLYZE-HTTP-HSTS-MISSING",
        "HSTS header missing",
        "The HTTP response does not include a Strict-Transport-Security header.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-HTTP-HSTS-MAX-AGE-MISSING",
        "HSTS max-age missing",
        "The Strict-Transport-Security header does not define a max-age directive.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-HTTP-HSTS-MAX-AGE-SHORT",
        "HSTS max-age too short",
        "The HSTS max-age is shorter than 180 days, which is below common deployment guidance.",
        Severity.NOTE,
    ),
    SarifRule(
        "SSLYZE-CERT-CHAIN-UNTRUSTED",
        "Certificate chain could not be trusted",
        "The deployed certificate chain could not be validated using any bundled trust store.",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-CERT-SHA1-SIGNATURE",
        "SHA-1 certificate signature",
        "At least one certificate in the verified chain is signed with SHA-1.",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-CERT-LEGACY-SYMANTEC-ANCHOR",
        "Distrusted legacy Symantec anchor",
        "The verified certificate chain contains a legacy Symantec anchor that is no longer trusted.",
        Severity.HIGH,
    ),
    SarifRule(
        "SSLYZE-CERT-CHAIN-INVALID-ORDER",
        "Certificate chain has invalid order",
        "The certificate chain sent by the server is not ordered from leaf to root.",
        Severity.MEDIUM,
    ),
    SarifRule(
        "SSLYZE-CERT-ANCHOR-INCLUDED",
        "Root certificate included in chain",
        "The server includes the trust anchor certificate in the chain it sends to clients.",
        Severity.NOTE,
    ),
    SarifRule(
        "SSLYZE-CERT-SCT-MISSING",
        "Certificate Transparency SCT missing",
        "The leaf certificate does not embed any Signed Certificate Timestamps.",
        Severity.NOTE,
    ),
    SarifRule(
        "SSLYZE-CERT-OCSP-UNTRUSTED",
        "OCSP response is untrusted",
        "The server returned an OCSP response that could not be verified using the selected trust store.",
        Severity.MEDIUM,
    ),
)

RULE_INDEX_BY_ID: Mapping[str, int] = {rule.rule_id: index for index, rule in enumerate(RULES)}
RULES_BY_ID: Mapping[str, SarifRule] = {rule.rule_id: rule for rule in RULES}


class SarifValidationError(ValueError):
    """Raised when an emitted object or a completed SARIF document is invalid."""


@dataclass(frozen=True)
class SarifFinding:
    rule_id: str
    message: str
    properties: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SarifSourceLocation:
    uri: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    snippet: Optional[str] = None


def _utc_timestamp(value: Optional[datetime] = None) -> str:
    final_value = value or datetime.now(timezone.utc)
    return final_value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _strip_absolute_path_prefix(path_as_text: str) -> str:
    path_as_text = path_as_text.replace("\\", "/")
    path_as_text = re.sub(r"^[A-Za-z]:", "", path_as_text)
    return path_as_text


def repository_root_for(start_path: Path) -> Path:
    """Find the nearest repository root, falling back to the supplied directory."""
    current_path = start_path.absolute()
    for candidate_path in (current_path, *current_path.parents):
        if (candidate_path / ".git").exists():
            return candidate_path
    return current_path


def relative_sarif_uri(path: Path, source_root: Path) -> str:
    """Return a relative, percent-escaped SARIF URI without leaking the local filesystem root."""
    source_path = os.fspath(path)
    root_path = os.fspath(source_root)

    try:
        relative_path = os.path.relpath(source_path, root_path)
    except ValueError:
        relative_path = os.path.basename(source_path)

    relative_path = _strip_absolute_path_prefix(relative_path).lstrip("/")
    while relative_path.startswith("./"):
        relative_path = relative_path[2:]

    if not relative_path or relative_path == ".." or relative_path.startswith("../"):
        relative_path = os.path.basename(source_path.replace("\\", "/"))

    return quote_from_bytes(os.fsencode(relative_path), safe="/-._~")


def source_location_for(
    source_path: Path,
    source_root: Path,
    line_number: int,
    line_text: str,
    start_column: int = 1,
) -> SarifSourceLocation:
    if line_number < 1:
        raise SarifValidationError(f"line_number must be >= 1, got {line_number}")
    if start_column < 1:
        raise SarifValidationError(f"start_column must be >= 1, got {start_column}")

    line_length = len(line_text)
    return SarifSourceLocation(
        uri=relative_sarif_uri(source_path, source_root),
        start_line=line_number,
        start_column=start_column,
        end_line=line_number,
        end_column=max(start_column + 1, line_length + 1),
        snippet=line_text,
    )


def _finding(rule_id: str, message: str, **properties: str) -> SarifFinding:
    return SarifFinding(rule_id=rule_id, message=message, properties=properties)


def _certificate_findings(result: CertificateInfoScanResult) -> Iterator[SarifFinding]:
    deployments = result.certificate_deployments
    if not deployments:
        return

    has_trusted_chain = any(
        path_result.was_validation_successful
        for deployment in deployments
        for path_result in deployment.path_validation_results
    )
    if not has_trusted_chain:
        yield _finding(
            "SSLYZE-CERT-CHAIN-UNTRUSTED",
            "The deployed certificate chain could not be trusted by any bundled trust store.",
        )

    if any(deployment.verified_chain_has_sha1_signature is True for deployment in deployments):
        yield _finding(
            "SSLYZE-CERT-SHA1-SIGNATURE",
            "At least one certificate in the verified chain is signed with SHA-1.",
        )

    if any(deployment.verified_chain_has_legacy_symantec_anchor is True for deployment in deployments):
        yield _finding(
            "SSLYZE-CERT-LEGACY-SYMANTEC-ANCHOR",
            "The verified certificate chain contains a distrusted legacy Symantec anchor.",
        )

    if any(deployment.received_chain_has_valid_order is False for deployment in deployments):
        yield _finding(
            "SSLYZE-CERT-CHAIN-INVALID-ORDER",
            "The certificate chain sent by the server is not ordered from leaf to root.",
        )

    if any(deployment.received_chain_contains_anchor_certificate is True for deployment in deployments):
        yield _finding(
            "SSLYZE-CERT-ANCHOR-INCLUDED",
            "The server includes the trust anchor certificate in the chain it sends to clients.",
        )

    if any(deployment.leaf_certificate_signed_certificate_timestamps_count == 0 for deployment in deployments):
        yield _finding(
            "SSLYZE-CERT-SCT-MISSING",
            "The leaf certificate does not embed any Signed Certificate Timestamps.",
        )

    if any(deployment.ocsp_response_is_trusted is False for deployment in deployments):
        yield _finding(
            "SSLYZE-CERT-OCSP-UNTRUSTED",
            "The server returned an OCSP response that could not be verified using the selected trust store.",
        )


_WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")


def _weak_cipher_suites(result: Any) -> List[str]:
    weak_suites = []
    for accepted_cipher_suite in result.accepted_cipher_suites:
        cipher_name = accepted_cipher_suite.cipher_suite.name
        upper_name = cipher_name.upper()
        if any(marker in upper_name for marker in _WEAK_CIPHER_MARKERS):
            weak_suites.append(cipher_name)
    return weak_suites


def _http_header_findings(result: HttpHeadersScanResult) -> Iterator[SarifFinding]:
    if result.http_error_trace:
        return

    hsts_header = result.strict_transport_security_header
    if hsts_header is None:
        yield _finding("SSLYZE-HTTP-HSTS-MISSING", "The HTTP response does not include an HSTS header.")
        return

    if hsts_header.max_age is None:
        yield _finding(
            "SSLYZE-HTTP-HSTS-MAX-AGE-MISSING",
            "The HSTS header does not define a max-age directive.",
        )
    elif hsts_header.max_age < 15552000:
        yield _finding(
            "SSLYZE-HTTP-HSTS-MAX-AGE-SHORT",
            f"The HSTS max-age is {hsts_header.max_age} seconds; 15552000 seconds (180 days) is recommended.",
        )


_TLS_VERSION_RULES: Mapping[ScanCommand, str] = {
    ScanCommand.SSL_2_0_CIPHER_SUITES: "SSLYZE-TLS-SSL20-SUPPORTED",
    ScanCommand.SSL_3_0_CIPHER_SUITES: "SSLYZE-TLS-SSL30-SUPPORTED",
    ScanCommand.TLS_1_0_CIPHER_SUITES: "SSLYZE-TLS-10-SUPPORTED",
    ScanCommand.TLS_1_1_CIPHER_SUITES: "SSLYZE-TLS-11-SUPPORTED",
}


def _completed_scan_command_findings(scan_command: ScanCommand, result: Any) -> Iterator[SarifFinding]:
    tls_version_rule_id = _TLS_VERSION_RULES.get(scan_command)
    if tls_version_rule_id and result.accepted_cipher_suites:
        yield _finding(
            tls_version_rule_id,
            f"The server accepted {scan_command.value.replace('_', ' ').upper()} cipher suites.",
            scan_command=scan_command.value,
            acceptedCipherSuiteCount=str(len(result.accepted_cipher_suites)),
        )

    if scan_command in {
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
    }:
        weak_cipher_suites = _weak_cipher_suites(result)
        if weak_cipher_suites:
            yield _finding(
                "SSLYZE-TLS-WEAK-CIPHER-SUITE",
                "The server accepts weak cipher suite(s): " + ", ".join(sorted(weak_cipher_suites)),
                scanCommand=scan_command.value,
                cipherSuites=",".join(sorted(weak_cipher_suites)),
            )

    if scan_command == ScanCommand.TLS_COMPRESSION and result.supports_compression:
        yield _finding(
            "SSLYZE-TLS-COMPRESSION",
            "The server enables TLS compression.",
        )

    if scan_command == ScanCommand.TLS_1_3_EARLY_DATA and result.supports_early_data:
        yield _finding(
            "SSLYZE-TLS-EARLY-DATA",
            "The server accepts TLS 1.3 early data.",
        )

    if scan_command == ScanCommand.OPENSSL_CCS_INJECTION and result.is_vulnerable_to_ccs_injection:
        yield _finding(
            "SSLYZE-TLS-OPENSSL-CCS-INJECTION",
            "The server is vulnerable to OpenSSL CCS injection.",
        )

    if scan_command == ScanCommand.TLS_FALLBACK_SCSV and not result.supports_fallback_scsv:
        yield _finding(
            "SSLYZE-TLS-FALLBACK-SCSV-MISSING",
            "The server does not support TLS fallback SCSV.",
        )

    if scan_command == ScanCommand.HEARTBLEED and result.is_vulnerable_to_heartbleed:
        yield _finding(
            "SSLYZE-TLS-HEARTBLEED",
            "The server is vulnerable to Heartbleed.",
        )

    if scan_command == ScanCommand.ROBOT:
        if result.robot_result == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE:
            yield _finding(
                "SSLYZE-TLS-ROBOT-STRONG-ORACLE",
                "The server exposes a strong ROBOT oracle.",
            )
        elif result.robot_result == RobotScanResultEnum.VULNERABLE_WEAK_ORACLE:
            yield _finding(
                "SSLYZE-TLS-ROBOT-WEAK-ORACLE",
                "The server exposes a weak ROBOT oracle.",
            )

    if scan_command == ScanCommand.SESSION_RENEGOTIATION:
        if not result.supports_secure_renegotiation:
            yield _finding(
                "SSLYZE-TLS-SECURE-RENEGOTIATION-MISSING",
                "The server does not support secure TLS renegotiation.",
            )
        if result.is_vulnerable_to_client_renegotiation_dos:
            yield _finding(
                "SSLYZE-TLS-CLIENT-RENEGOTIATION-DOS",
                "The server honors client-initiated renegotiation.",
            )

    if scan_command == ScanCommand.TLS_EXTENDED_MASTER_SECRET and not result.supports_ems_extension:
        yield _finding(
            "SSLYZE-TLS-EMS-MISSING",
            "The server does not support the TLS Extended Master Secret extension.",
        )

    if scan_command == ScanCommand.CERTIFICATE_INFO:
        yield from _certificate_findings(result)

    if scan_command == ScanCommand.HTTP_HEADERS:
        yield from _http_header_findings(result)


def iter_findings_for_server_scan_result(server_scan_result: ServerScanResult) -> Iterator[SarifFinding]:
    if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
        yield _finding(
            "SSLYZE-SCAN-CONNECTIVITY-FAILED",
            f"Could not establish a TLS connection to {server_scan_result.server_location.display_string}.",
        )
        return

    scan_result = server_scan_result.scan_result
    if not scan_result:
        return

    for result_field in fields(scan_result):
        scan_command = ScanCommand(result_field.name)
        attempt = getattr(scan_result, result_field.name)

        if attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            error_reason = attempt.error_reason.value if attempt.error_reason else "UNKNOWN"
            yield _finding(
                "SSLYZE-SCAN-COMMAND-FAILED",
                f"The {scan_command.value} scan command failed ({error_reason}).",
                scanCommand=scan_command.value,
                errorReason=error_reason,
            )
        elif attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and attempt.result is not None:
            yield from _completed_scan_command_findings(scan_command, attempt.result)


def _rule_descriptor(rule: SarifRule) -> Dict[str, Any]:
    sarif_level = SEVERITY_TO_SARIF_LEVEL[rule.severity]
    return {
        "id": rule.rule_id,
        "name": rule.name,
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "helpUri": rule.help_uri,
        "defaultConfiguration": {"level": sarif_level},
        "properties": {"security-severity": sarif_level, "severity": rule.severity.value},
    }


def _validate_relative_uri(uri: str, field_path: str) -> None:
    if not uri:
        raise SarifValidationError(f"{field_path}: uri must not be empty")
    if uri.startswith("/") or uri.startswith("\\") or uri.startswith("../"):
        raise SarifValidationError(f"{field_path}: uri must be relative to the repository root, got {uri!r}")
    if re.match(r"^[A-Za-z]:", uri):
        raise SarifValidationError(f"{field_path}: uri must not contain a Windows drive letter, got {uri!r}")
    if "://" in uri:
        raise SarifValidationError(f"{field_path}: uri must not be an absolute URI, got {uri!r}")


def _validate_sarif_result(result: Mapping[str, Any], result_index: int) -> None:
    prefix = f"runs[0].results[{result_index}]"
    if result.get("ruleId") not in RULES_BY_ID:
        raise SarifValidationError(f"{prefix}.ruleId: unknown ruleId {result.get('ruleId')!r}")
    if result.get("level") not in SEVERITY_TO_SARIF_LEVEL.values():
        raise SarifValidationError(f"{prefix}.level: invalid SARIF level {result.get('level')!r}")
    message = result.get("message")
    if not isinstance(message, Mapping) or not isinstance(message.get("text"), str):
        raise SarifValidationError(f"{prefix}.message.text: must be a non-empty string")

    locations = result.get("locations")
    if not isinstance(locations, Sequence) or not locations:
        raise SarifValidationError(f"{prefix}.locations: must contain at least one location")

    for location_index, location in enumerate(locations):
        location_prefix = f"{prefix}.locations[{location_index}]"
        physical_location = location.get("physicalLocation") if isinstance(location, Mapping) else None
        if not isinstance(physical_location, Mapping):
            raise SarifValidationError(f"{location_prefix}.physicalLocation: is required")

        artifact_location = physical_location.get("artifactLocation")
        if not isinstance(artifact_location, Mapping):
            raise SarifValidationError(f"{location_prefix}.physicalLocation.artifactLocation: is required")
        artifact_uri = artifact_location.get("uri")
        if not isinstance(artifact_uri, str):
            raise SarifValidationError(f"{location_prefix}.physicalLocation.artifactLocation.uri: is required")
        _validate_relative_uri(artifact_uri, f"{location_prefix}.physicalLocation.artifactLocation.uri")

        region = physical_location.get("region")
        if not isinstance(region, Mapping):
            raise SarifValidationError(f"{location_prefix}.physicalLocation.region: is required")
        for field_name in ("startLine", "startColumn", "endLine", "endColumn"):
            field_value = region.get(field_name)
            if not isinstance(field_value, int) or field_value < 1:
                raise SarifValidationError(
                    f"{location_prefix}.physicalLocation.region.{field_name}: must be an integer >= 1"
                )
        if region["endLine"] < region["startLine"]:
            raise SarifValidationError(f"{location_prefix}.physicalLocation.region.endLine: must be >= startLine")
        if region["endLine"] == region["startLine"] and region["endColumn"] <= region["startColumn"]:
            raise SarifValidationError(f"{location_prefix}.physicalLocation.region.endColumn: must be > startColumn")


class _ChunkedTextWriter:
    def __init__(self, file_to: TextIO, chunk_size: int) -> None:
        self._file_to = file_to
        self._chunk_size = chunk_size
        self._chunks: List[str] = []
        self._buffered_bytes = 0
        self.chunk_count = 0

    def write(self, value: str) -> None:
        self._chunks.append(value)
        self._buffered_bytes += len(value)
        if self._buffered_bytes >= self._chunk_size:
            self.flush()

    def flush(self) -> None:
        if not self._chunks:
            return
        self._file_to.write("".join(self._chunks))
        self.chunk_count += 1
        self._chunks = []
        self._buffered_bytes = 0

    @property
    def buffered_bytes(self) -> int:
        return self._buffered_bytes


class SarifOutputWriter:
    """Incrementally write one SARIF 2.1.0 run and atomically publish it on success."""

    def __init__(
        self,
        output_path: Path,
        *,
        source_root: Path,
        start_time: Optional[datetime] = None,
        chunk_size: int = 65536,
    ) -> None:
        self._output_path = output_path
        self._source_root = source_root
        self._start_time = start_time or datetime.now(timezone.utc)
        self._chunk_size = chunk_size
        self._lock = threading.RLock()
        self._temp_path: Optional[Path] = None
        self._file: Optional[TextIO] = None
        self._chunk_writer: Optional[_ChunkedTextWriter] = None
        self._result_count = 0
        self._execution_successful = True
        self._notifications: List[Dict[str, Any]] = []
        self._finished = False

    def __enter__(self) -> "SarifOutputWriter":
        self.open()
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if exc_type is not None:
            self.abort(reason=f"aborted after {exc_type.__name__}: {exc_value}")
        elif not self._finished:
            try:
                self.finish()
            except Exception:
                self.abort(reason="failed while finalizing SARIF output")
                raise

    @property
    def result_count(self) -> int:
        return self._result_count

    @property
    def chunk_count(self) -> int:
        return self._chunk_writer.chunk_count if self._chunk_writer else 0

    def open(self) -> None:
        if self._file is not None:
            raise RuntimeError("SARIF output writer is already open")

        _logger.info('SARIF output: entering; writing to "%s"', self._output_path)
        file_descriptor: Optional[int] = None
        try:
            parent_path = self._output_path.parent
            file_descriptor, temp_path_as_str = tempfile.mkstemp(
                dir=os.fspath(parent_path),
                prefix=f".{self._output_path.name}.",
                suffix=".tmp",
            )
            self._temp_path = Path(temp_path_as_str)
            self._file = os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n")
            self._chunk_writer = _ChunkedTextWriter(self._file, self._chunk_size)

            tool = {
                "driver": {
                    "name": "SSLyze",
                    "version": __version__,
                    "informationUri": __url__,
                    "rules": [_rule_descriptor(rule) for rule in RULES],
                }
            }
            header = {
                "version": "2.1.0",
                "$schema": SARIF_SCHEMA_URI,
                "runs": [{"tool": tool, "results": []}],
            }
            header_as_json = json.dumps(header, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
            # Replace the empty results array with the streaming array opener.
            results_marker = '"results":[]'
            results_marker_index = header_as_json.index(results_marker)
            prefix_without_results = header_as_json[:results_marker_index] + '"results":'
            self._chunk_writer.write(prefix_without_results + "[")
            self._chunk_writer.flush()
        except Exception as e:
            if self._file is None and file_descriptor is not None:
                os.close(file_descriptor)
            self.abort(reason=f"could not initialize output: {e}")
            raise

    def _write_result(self, result: Mapping[str, Any]) -> None:
        with self._lock:
            if self._chunk_writer is None:
                raise RuntimeError("SARIF output writer is not open")

            _validate_sarif_result(result, self._result_count)
            result_as_json = json.dumps(
                result,
                ensure_ascii=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            if self._result_count:
                self._chunk_writer.write(",")
            self._chunk_writer.write(result_as_json)
            self._result_count += 1

    def _result_for_finding(self, finding: SarifFinding, location: SarifSourceLocation) -> Dict[str, Any]:
        rule = RULES_BY_ID[finding.rule_id]
        region: Dict[str, Any] = {
            "startLine": location.start_line,
            "startColumn": location.start_column,
            "endLine": location.end_line,
            "endColumn": location.end_column,
        }
        if location.snippet is not None:
            region["snippet"] = {"text": location.snippet}

        result: Dict[str, Any] = {
            "ruleId": rule.rule_id,
            "ruleIndex": RULE_INDEX_BY_ID[rule.rule_id],
            "level": SEVERITY_TO_SARIF_LEVEL[rule.severity],
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": location.uri},
                        "region": region,
                    }
                }
            ],
        }
        if finding.properties:
            result["properties"] = dict(finding.properties)
        return result

    def write_finding(
        self,
        finding: SarifFinding,
        *,
        source_path: Path,
        line_number: int,
        line_text: str,
    ) -> None:
        if finding.rule_id not in RULES_BY_ID:
            raise SarifValidationError(
                f"runs[0].results[{self._result_count}].ruleId: unknown ruleId {finding.rule_id!r}"
            )
        if not finding.message:
            raise SarifValidationError(f"runs[0].results[{self._result_count}].message.text: must not be empty")
        location = source_location_for(source_path, self._source_root, line_number, line_text)
        self._write_result(self._result_for_finding(finding, location))

    def write_invalid_server(
        self,
        server_string: str,
        error_message: str,
        *,
        source_path: Path,
        line_number: int,
        line_text: str,
    ) -> None:
        with self._lock:
            self._execution_successful = False
        self.write_finding(
            _finding(
                "SSLYZE-TARGET-INVALID",
                f"The target {server_string!r} could not be scanned: {error_message}",
                serverString=server_string,
                errorMessage=error_message,
            ),
            source_path=source_path,
            line_number=line_number,
            line_text=line_text,
        )

    def write_server_scan_result(
        self,
        server_scan_result: ServerScanResult,
        *,
        source_path: Path,
        line_number: int,
        line_text: str,
    ) -> None:
        with self._lock:
            if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                self._execution_successful = False
                if len(self._notifications) < _MAX_TOOL_NOTIFICATIONS:
                    self._notifications.append(
                        {
                            "level": "error",
                            "message": {
                                "text": (
                                    f"TLS connectivity failed for "
                                    f"{server_scan_result.server_location.display_string}."
                                )
                            },
                        }
                    )
            elif server_scan_result.scan_result:
                for result_field in fields(server_scan_result.scan_result):
                    attempt = getattr(server_scan_result.scan_result, result_field.name)
                    if attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                        self._execution_successful = False

        for finding in iter_findings_for_server_scan_result(server_scan_result):
            self.write_finding(
                finding,
                source_path=source_path,
                line_number=line_number,
                line_text=line_text,
            )

    def write_server_scan_results(
        self,
        results: Iterable[Tuple[ServerScanResult, Path, int, str]],
    ) -> None:
        for server_scan_result, source_path, line_number, line_text in results:
            self.write_server_scan_result(
                server_scan_result,
                source_path=source_path,
                line_number=line_number,
                line_text=line_text,
            )

    def finish(self) -> None:
        with self._lock:
            if self._finished:
                return
            if self._chunk_writer is None or self._file is None:
                raise RuntimeError("SARIF output writer is not open")

            self._chunk_writer.flush()
            invocation: Dict[str, Any] = {
                "executionSuccessful": self._execution_successful,
                "startTimeUtc": _utc_timestamp(self._start_time),
                "endTimeUtc": _utc_timestamp(),
            }
            if self._notifications:
                invocation["toolExecutionNotifications"] = self._notifications

            footer = {
                "invocations": [invocation],
            }
            footer_as_json = json.dumps(footer, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
            self._chunk_writer.write("]," + footer_as_json[1:-1] + "}]}")
            self._chunk_writer.flush()

            self._file.flush()
            os.fsync(self._file.fileno())
            self._file.close()
            self._file = None

            assert self._temp_path is not None
            os.replace(self._temp_path, self._output_path)
            self._temp_path = None
            self._finished = True

        _logger.info(
            'SARIF output: completed; wrote %d result(s) to "%s"',
            self._result_count,
            self._output_path,
        )

    def abort(self, *, reason: str) -> None:
        with self._lock:
            _logger.error('SARIF output: failed; %s (temporary file for "%s" removed)', reason, self._output_path)
            if self._file is not None:
                try:
                    self._file.close()
                finally:
                    self._file = None
            self._chunk_writer = None
            if self._temp_path is not None:
                try:
                    self._temp_path.unlink()
                except FileNotFoundError:
                    pass
                finally:
                    self._temp_path = None


def validate_sarif_file(
    sarif_path: Path,
    schema_path: Optional[Path] = None,
    *,
    max_errors: int = 50,
) -> None:
    """Validate a SARIF file with the official schema and report precise JSON/schema paths."""
    try:
        import jsonschema
    except ImportError as e:
        raise SarifValidationError(
            "jsonschema is required for SARIF schema validation; install the 'jsonschema' package"
        ) from e

    schema = json.loads((schema_path or SARIF_SCHEMA_PATH).read_text(encoding="utf-8"))
    instance = json.loads(sarif_path.read_text(encoding="utf-8"))
    validator = jsonschema.validators.validator_for(schema)(schema)
    validation_errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: [str(path_element) for path_element in error.absolute_path],
    )
    if not validation_errors:
        return

    error_lines = []
    for validation_error in validation_errors[:max_errors]:
        instance_path = "$"
        for path_element in validation_error.absolute_path:
            if isinstance(path_element, int):
                instance_path += f"[{path_element}]"
            else:
                instance_path += f".{path_element}"

        schema_path_as_text = "$"
        for path_element in validation_error.absolute_schema_path:
            if isinstance(path_element, int):
                schema_path_as_text += f"[{path_element}]"
            else:
                schema_path_as_text += f".{path_element}"

        error_lines.append(f"{instance_path} (schema {schema_path_as_text}): {validation_error.message}")

    remaining_errors_count = len(validation_errors) - len(error_lines)
    if remaining_errors_count:
        error_lines.append(f"... and {remaining_errors_count} more schema error(s)")

    raise SarifValidationError(
        f"SARIF schema validation failed with {len(validation_errors)} error(s):\n" + "\n".join(error_lines)
    )

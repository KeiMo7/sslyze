Exporting scan results as SARIF 2.1.0
#####################################

SSLyze can emit a SARIF 2.1.0 document for security dashboards and code-scanning
platforms. SARIF output is opt-in and does not change the console table or the
existing ``--json_out`` output.

CLI usage
*********

Use ``--sarif_out`` with either direct targets or ``--targets_in``::

    $ python -m sslyze --targets_in=targets.txt --sarif_out=sslyze.sarif

The existing JSON output can be requested at the same time if needed::

    $ python -m sslyze --targets_in=targets.txt \
        --json_out=sslyze.json --sarif_out=sslyze.sarif

Migration from JSON-only automation
***********************************

An existing JSON workflow does not need to change::

    # Before
    $ python -m sslyze --targets_in=targets.txt --json_out=sslyze.json

    # After: keep JSON and add SARIF
    $ python -m sslyze --targets_in=targets.txt \
        --json_out=sslyze.json --sarif_out=sslyze.sarif

``--sarif_out`` is disabled by default. When it is not supplied, the default
command-line parsing, scan scheduling, console output, JSON output and exit
codes are unchanged.

Locations and rules
*******************

SSLyze scans remote TLS endpoints rather than local source files. Each SARIF
physical location therefore points at the target definition that produced the
finding:

* With ``--targets_in``, the URI is the targets file path relative to the
  current repository root, and the line/column range points at the exact target
  line in that file.
* With targets passed directly on the command line, the URI is the synthetic
  ``sslyze-targets.txt`` and line numbers follow the command-line target order.

Every rule hit is an independent SARIF result. The same rule can appear many
times in one file when several target lines trigger it. Rule IDs are static and
version-independent (for example, ``SSLYZE-TLS-HEARTBLEED``); they never include
paths, timestamps or random values.

The explicit severity mapping is:

==========  =================
SSLyze      SARIF ``level``
==========  =================
High        ``error``
Medium      ``warning``
Note        ``note``
==========  =================

Validation and failure handling
*******************************

SARIF is written incrementally to a temporary file in the destination directory
and atomically moved into place only after the scan and report footer complete.
If the process fails before that point, the temporary file is removed and an
existing destination file is left untouched.

Each result is checked for required SARIF fields and relative URI safety before
it is serialized. The bundled official schema can be used for a full-document
check::

    python - <<'PY'
    from pathlib import Path
    from sslyze.json.sarif_output import validate_sarif_file

    validate_sarif_file(Path("sslyze.sarif"))
    PY

Validation errors identify both the JSON instance path and the schema path,
for example ``runs[0].results[0].level``.

Known limitations
*****************

* SSLyze cannot point at a remote server's source statement; locations point at
  the local target definition line instead.
* Direct command-line targets share the synthetic ``sslyze-targets.txt`` URI;
  use ``--targets_in`` when stable source-control locations are required.
* ``--sarif_out`` writes to a file only. ``-`` is rejected so a failed run can
  never leave a partial JSON document on stdout.
* Findings are emitted as the scanner completes each server. The caller must
  serialize writes through one writer instance; concurrent server scans do not
  change, and result serialization remains on the consuming thread.

"""
GRC Engineering Playbook: reference implementations for continuous compliance
automation on AWS.

Stdlib only (except the optional boto3 collector). Most modules expose
run(data_dir) and are wired into the CLI; grc_api.py is a client library, and
webhook.py / mock_grc_api.py / collect_aws.py have their own entry points.
"""
from pathlib import Path

__version__ = "0.1.0"

# repo root is two levels up from src/grc_playbook/
REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = REPO_ROOT / "examples"

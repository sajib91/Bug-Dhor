"""Controlled code corpus for real-model counterfactual validation experiments.

The samples are *synthetic, lexically varied* Python snippets.  Each category
contains one vulnerable pattern and one secure counterpart.  The labels describe
the pattern used to generate the snippet; they are not validated ground truth
about a model's behaviour and must not be reported as vulnerability detection
accuracy.

The same snippets are used for two separate purposes:

* ``role == "eval"``: the experimental units on which interaction contrasts are
  estimated.
* ``role == "train"``: additional prompts whose token-level activations are used
  to train the sparse autoencoder.  SAE training is unsupervised and does not
  use the labels or the outcome.
"""

from __future__ import annotations

from dataclasses import dataclass

LABEL_TOKEN_CANDIDATES: tuple[tuple[str, str], ...] = (
    (" A", " B"),
    ("A", "B"),
    (" yes", " no"),
    (" unsafe", " safe"),
)

PROMPT_PREFIX = "Review the following Python code for security problems.\n\n```python\n"
PROMPT_SUFFIX = (
    '\n```\n\nIf the code is unsafe, answer "A". If the code is safe, answer "B".\nAnswer:'
)

_VARIANTS: tuple[dict[str, str], ...] = (
    {
        "func": "load_user",
        "table": "users",
        "route": "profile",
        "path": "uploads",
        "secret": "DB_PASSWORD",
    },
    {
        "func": "fetch_record",
        "table": "accounts",
        "route": "account",
        "path": "files",
        "secret": "API_TOKEN",
    },
    {
        "func": "get_account",
        "table": "orders",
        "route": "order",
        "path": "static",
        "secret": "SECRET_KEY",
    },
    {
        "func": "read_profile",
        "table": "profiles",
        "route": "record",
        "path": "data",
        "secret": "ADMIN_PASS",
    },
    {
        "func": "find_item",
        "table": "items",
        "route": "item",
        "path": "assets",
        "secret": "SERVICE_KEY",
    },
    {
        "func": "lookup_order",
        "table": "records",
        "route": "user",
        "path": "docs",
        "secret": "AUTH_SECRET",
    },
)

_TEMPLATES: dict[str, dict[str, str]] = {
    "CWE-89": {
        "vulnerable": """\
import sqlite3


def {func}(user_input):
    connection = sqlite3.connect("{table}.db")
    cursor = connection.cursor()
    query = "SELECT * FROM {table} WHERE name = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()
""",
        "secure": """\
import sqlite3


def {func}(user_input):
    connection = sqlite3.connect("{table}.db")
    cursor = connection.cursor()
    query = "SELECT * FROM {table} WHERE name = ?"
    cursor.execute(query, (user_input,))
    return cursor.fetchall()
""",
    },
    "CWE-79": {
        "vulnerable": """\
from flask import Flask, request

app = Flask(__name__)


@app.route("/{route}")
def {func}():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"
""",
        "secure": """\
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/{route}")
def {func}():
    name = request.args.get("name", "")
    return "<h1>Hello " + str(escape(name)) + "</h1>"
""",
    },
    "CWE-78": {
        "vulnerable": """\
import os


def {func}(filename):
    os.system("cat " + filename)
""",
        "secure": """\
import subprocess


def {func}(filename):
    subprocess.run(["cat", filename], check=True)
""",
    },
    "CWE-22": {
        "vulnerable": """\
import os


def {func}(name):
    base = "/srv/{path}/"
    return open(os.path.join(base, name)).read()
""",
        "secure": """\
import os


def {func}(name):
    base = os.path.realpath("/srv/{path}/")
    candidate = os.path.realpath(os.path.join(base, name))
    if not candidate.startswith(base + os.sep):
        raise ValueError("invalid path")
    return open(candidate).read()
""",
    },
    "CWE-798": {
        "vulnerable": """\
import hashlib


def {func}():
    password = "{secret}"
    return hashlib.sha256(password.encode()).hexdigest()
""",
        "secure": """\
import os
import hashlib


def {func}():
    password = os.environ["{secret}"]
    return hashlib.sha256(password.encode()).hexdigest()
""",
    },
    "CWE-502": {
        "vulnerable": """\
import pickle


def {func}(data):
    return pickle.loads(data)
""",
        "secure": """\
import json


def {func}(data):
    return json.loads(data)
""",
    },
}


@dataclass(frozen=True, slots=True)
class ValidationSample:
    """One generated code sample and its instruction-conditioned prompt."""

    sample_id: str
    cwe: str
    label: str
    role: str
    variant: int
    code: str
    prompt: str


def build_prompt(code: str) -> str:
    """Wrap code in the fixed outcome-probe instruction."""
    if not code.strip():
        raise ValueError("code must not be empty")
    return PROMPT_PREFIX + code.rstrip() + PROMPT_SUFFIX


def build_validation_corpus(
    *,
    eval_variants: int = 2,
    train_variants: int = 4,
) -> tuple[ValidationSample, ...]:
    """Generate the controlled corpus deterministically.

    With the defaults each of the six categories contributes two vulnerable and
    two secure evaluation samples (24 units) and eight training samples (48
    prompts).  Variant ordering is fixed so the corpus is reproducible.
    """
    if eval_variants < 1 or train_variants < 0:
        raise ValueError("eval_variants must be positive and train_variants non-negative")
    if eval_variants + train_variants > len(_VARIANTS):
        raise ValueError("requested more variants than are defined")
    samples: list[ValidationSample] = []
    for cwe, templates in _TEMPLATES.items():
        for label, template in templates.items():
            for variant in range(eval_variants + train_variants):
                substitutions = _VARIANTS[variant]
                code = template.format(**substitutions)
                role = "eval" if variant < eval_variants else "train"
                samples.append(
                    ValidationSample(
                        sample_id=f"{cwe}-{label}-{variant}",
                        cwe=cwe,
                        label=label,
                        role=role,
                        variant=variant,
                        code=code,
                        prompt=build_prompt(code),
                    )
                )
    return tuple(samples)


def split_roles(
    samples: tuple[ValidationSample, ...],
) -> tuple[tuple[ValidationSample, ...], tuple[ValidationSample, ...]]:
    """Return ``(eval_samples, train_samples)`` preserving corpus order."""
    evaluation = tuple(sample for sample in samples if sample.role == "eval")
    training = tuple(sample for sample in samples if sample.role == "train")
    return evaluation, training


def decode_label_tokens(tokenizer: object) -> tuple[int, int, str, str]:
    """Resolve a single-token A/B label pair for the outcome probe.

    The probe asks the model to answer ``A`` or ``B``; the outcome is the
    difference between the next-token logits of those two labels.  Only a pair
    that tokenizes to exactly one token each is accepted.
    """
    encode = getattr(tokenizer, "encode", None)
    if encode is None:
        raise TypeError("tokenizer must expose an encode method")
    for first, second in LABEL_TOKEN_CANDIDATES:
        first_ids = encode(first, add_special_tokens=False)
        second_ids = encode(second, add_special_tokens=False)
        if len(first_ids) == 1 and len(second_ids) == 1:
            return first_ids[0], second_ids[0], first, second
    raise ValueError("no candidate label pair tokenizes to single tokens")


__all__ = [
    "LABEL_TOKEN_CANDIDATES",
    "PROMPT_PREFIX",
    "PROMPT_SUFFIX",
    "ValidationSample",
    "build_prompt",
    "build_validation_corpus",
    "decode_label_tokens",
    "split_roles",
]

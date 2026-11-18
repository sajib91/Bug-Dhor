"""Transparent vulnerability and CWE classification.

Classification is rule-, metadata-, and evidence-driven. A category is selected
from the evidence that actually supports it; the engine does not assign a CWE
just because a category exists in a mapping table. When no category or CWE can
be supported, the candidate is retained as unclassified instead of receiving a
plausible-looking identifier.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from bugdhor.detection.models import (
    CweSupport,
    EvidenceItem,
    VulnerabilityCategory,
)
from bugdhor.static.cwe import extract_cwes, normalize_cwe

_CWE_TO_CATEGORY: dict[str, VulnerabilityCategory] = {
    "CWE-89": VulnerabilityCategory.SQL_INJECTION,
    "CWE-564": VulnerabilityCategory.SQL_INJECTION,
    "CWE-943": VulnerabilityCategory.SQL_INJECTION,
    "CWE-78": VulnerabilityCategory.COMMAND_INJECTION,
    "CWE-77": VulnerabilityCategory.COMMAND_INJECTION,
    "CWE-74": VulnerabilityCategory.COMMAND_INJECTION,
    "CWE-88": VulnerabilityCategory.COMMAND_INJECTION,
    "CWE-94": VulnerabilityCategory.CODE_INJECTION,
    "CWE-95": VulnerabilityCategory.CODE_INJECTION,
    "CWE-96": VulnerabilityCategory.CODE_INJECTION,
    "CWE-97": VulnerabilityCategory.CODE_INJECTION,
    "CWE-1336": VulnerabilityCategory.CODE_INJECTION,
    "CWE-79": VulnerabilityCategory.XSS,
    "CWE-80": VulnerabilityCategory.XSS,
    "CWE-83": VulnerabilityCategory.XSS,
    "CWE-116": VulnerabilityCategory.XSS,
    "CWE-22": VulnerabilityCategory.PATH_TRAVERSAL,
    "CWE-23": VulnerabilityCategory.PATH_TRAVERSAL,
    "CWE-36": VulnerabilityCategory.PATH_TRAVERSAL,
    "CWE-73": VulnerabilityCategory.PATH_TRAVERSAL,
    "CWE-502": VulnerabilityCategory.UNSAFE_DESERIALIZATION,
    "CWE-915": VulnerabilityCategory.UNSAFE_DESERIALIZATION,
    "CWE-798": VulnerabilityCategory.HARDCODED_SECRET,
    "CWE-259": VulnerabilityCategory.HARDCODED_SECRET,
    "CWE-321": VulnerabilityCategory.HARDCODED_SECRET,
    "CWE-522": VulnerabilityCategory.HARDCODED_SECRET,
    "CWE-327": VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
    "CWE-328": VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
    "CWE-326": VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
    "CWE-916": VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
    "CWE-295": VulnerabilityCategory.INSECURE_TLS,
    "CWE-297": VulnerabilityCategory.INSECURE_TLS,
    "CWE-319": VulnerabilityCategory.INSECURE_TLS,
    "CWE-611": VulnerabilityCategory.XXE,
    "CWE-918": VulnerabilityCategory.SSRF,
    "CWE-601": VulnerabilityCategory.OPEN_REDIRECT,
    "CWE-352": VulnerabilityCategory.CSRF,
    "CWE-287": VulnerabilityCategory.AUTH_BYPASS,
    "CWE-306": VulnerabilityCategory.AUTH_BYPASS,
    "CWE-862": VulnerabilityCategory.AUTH_BYPASS,
    "CWE-20": VulnerabilityCategory.INPUT_VALIDATION,
}


@dataclass(frozen=True, slots=True)
class CategoryInfo:
    title: str
    default_cwe: str
    remediation: str
    base_severity: str


CATEGORY_INFO: dict[VulnerabilityCategory, CategoryInfo] = {
    VulnerabilityCategory.SQL_INJECTION: CategoryInfo(
        title="SQL injection",
        default_cwe="CWE-89",
        remediation=(
            "Use parameterized queries or a query builder. Do not concatenate, "
            "format, or template untrusted values into SQL text."
        ),
        base_severity="high",
    ),
    VulnerabilityCategory.COMMAND_INJECTION: CategoryInfo(
        title="Command injection",
        default_cwe="CWE-78",
        remediation=(
            "Avoid shell interpretation. Pass an argument vector with shell "
            "execution disabled and validate or allowlist every component."
        ),
        base_severity="critical",
    ),
    VulnerabilityCategory.CODE_INJECTION: CategoryInfo(
        title="Code injection",
        default_cwe="CWE-95",
        remediation=(
            "Remove dynamic code execution. Use a constrained interpreter or "
            "an explicit allowlist of supported operations instead."
        ),
        base_severity="critical",
    ),
    VulnerabilityCategory.XSS: CategoryInfo(
        title="Cross-site scripting",
        default_cwe="CWE-79",
        remediation=(
            "Contextually encode untrusted output and rely on framework "
            "auto-escaping. Avoid raw HTML sinks and unsafe template strings."
        ),
        base_severity="high",
    ),
    VulnerabilityCategory.PATH_TRAVERSAL: CategoryInfo(
        title="Path traversal",
        default_cwe="CWE-22",
        remediation=(
            "Resolve the requested path under a fixed root, reject escapes, and "
            "prefer allowlisted filenames over user-controlled path components."
        ),
        base_severity="high",
    ),
    VulnerabilityCategory.UNSAFE_DESERIALIZATION: CategoryInfo(
        title="Unsafe deserialization",
        default_cwe="CWE-502",
        remediation=(
            "Do not deserialize untrusted data with executable formats. Use a "
            "data-only format and an explicit safe loader."
        ),
        base_severity="critical",
    ),
    VulnerabilityCategory.HARDCODED_SECRET: CategoryInfo(
        title="Hardcoded secret",
        default_cwe="CWE-798",
        remediation=(
            "Remove the credential from source, rotate it, and load secrets from "
            "a managed secret store or environment configuration."
        ),
        base_severity="high",
    ),
    VulnerabilityCategory.WEAK_CRYPTOGRAPHY: CategoryInfo(
        title="Weak cryptography",
        default_cwe="CWE-327",
        remediation=(
            "Use a current, approved cryptographic primitive with adequate key "
            "lengths, such as SHA-256 or stronger for integrity and Argon2id or "
            "scrypt for password storage."
        ),
        base_severity="medium",
    ),
    VulnerabilityCategory.INSECURE_TLS: CategoryInfo(
        title="Insecure TLS verification",
        default_cwe="CWE-295",
        remediation=(
            "Enable certificate and hostname verification. Do not disable "
            "verification or trust-all certificate callbacks in production."
        ),
        base_severity="high",
    ),
    VulnerabilityCategory.XXE: CategoryInfo(
        title="XML external entity",
        default_cwe="CWE-611",
        remediation=(
            "Disable external entities and DTD processing in the XML parser, or "
            "use a hardened parser configuration."
        ),
        base_severity="high",
    ),
    VulnerabilityCategory.SSRF: CategoryInfo(
        title="Server-side request forgery",
        default_cwe="CWE-918",
        remediation=(
            "Validate outbound destinations against an allowlist, resolve and "
            "re-check addresses, and block private or link-local ranges."
        ),
        base_severity="high",
    ),
    VulnerabilityCategory.OPEN_REDIRECT: CategoryInfo(
        title="Open redirect",
        default_cwe="CWE-601",
        remediation=(
            "Redirect only to a fixed destination or an allowlisted relative path, "
            "and never trust a user-supplied absolute URL."
        ),
        base_severity="medium",
    ),
    VulnerabilityCategory.CSRF: CategoryInfo(
        title="Cross-site request forgery",
        default_cwe="CWE-352",
        remediation=(
            "Require anti-CSRF tokens for state-changing requests and use "
            "SameSite cookies on top of server-side validation."
        ),
        base_severity="high",
    ),
    VulnerabilityCategory.AUTH_BYPASS: CategoryInfo(
        title="Authentication or authorization bypass",
        default_cwe="CWE-287",
        remediation=(
            "Enforce authentication and authorization on every protected path, "
            "fail closed, and add negative tests for missing or forged identity."
        ),
        base_severity="critical",
    ),
    VulnerabilityCategory.INPUT_VALIDATION: CategoryInfo(
        title="Improper input validation",
        default_cwe="CWE-20",
        remediation=(
            "Validate input against an explicit allowlist as close to the trust "
            "boundary as possible and reject malformed values."
        ),
        base_severity="medium",
    ),
}

CATEGORY_ORDER: tuple[VulnerabilityCategory, ...] = (
    VulnerabilityCategory.SQL_INJECTION,
    VulnerabilityCategory.COMMAND_INJECTION,
    VulnerabilityCategory.CODE_INJECTION,
    VulnerabilityCategory.XSS,
    VulnerabilityCategory.PATH_TRAVERSAL,
    VulnerabilityCategory.UNSAFE_DESERIALIZATION,
    VulnerabilityCategory.HARDCODED_SECRET,
    VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
    VulnerabilityCategory.INSECURE_TLS,
    VulnerabilityCategory.XXE,
    VulnerabilityCategory.SSRF,
    VulnerabilityCategory.OPEN_REDIRECT,
    VulnerabilityCategory.CSRF,
    VulnerabilityCategory.AUTH_BYPASS,
    VulnerabilityCategory.INPUT_VALIDATION,
    VulnerabilityCategory.UNKNOWN,
)

# Ordered patterns. Specific multi-word rules must precede generic tokens.
_CATEGORY_PATTERNS: tuple[tuple[VulnerabilityCategory, tuple[str, ...]], ...] = (
    (
        VulnerabilityCategory.UNSAFE_DESERIALIZATION,
        (
            "unsafe-deserialization",
            "unsafe_deserialization",
            "deserialization",
            "deserialisation",
            "pickle",
            "marshal.load",
            "yaml.load",
            "yaml-unsafe-load",
            "objectinputstream",
        ),
    ),
    (
        VulnerabilityCategory.SQL_INJECTION,
        (
            "sql-injection",
            "sql_injection",
            "sqli",
            "formatted-sql",
            "raw-sql",
            "raw_sql",
            "sql-query",
            "sql_query",
            "tainted-sql",
        ),
    ),
    (
        VulnerabilityCategory.COMMAND_INJECTION,
        (
            "command-injection",
            "command_injection",
            "os-command",
            "os_command",
            "shell-injection",
            "subprocess-shell",
            "shell-true",
            "child-process",
            "child_process",
            "dangerous-subprocess",
        ),
    ),
    (
        VulnerabilityCategory.XSS,
        (
            "cross-site-scripting",
            "cross_site_scripting",
            "xss",
            "html-injection",
            "innerhtml",
            "dangerouslysetinnerhtml",
            "template-injection",
        ),
    ),
    (
        VulnerabilityCategory.PATH_TRAVERSAL,
        (
            "path-traversal",
            "path_traversal",
            "directory-traversal",
            "directory_traversal",
            "local-file-inclusion",
            "unsafe-path",
            "zip-slip",
        ),
    ),
    (
        VulnerabilityCategory.CODE_INJECTION,
        (
            "code-injection",
            "code_injection",
            "eval",
            "exec",
            "dynamic-code",
            "function-constructor",
        ),
    ),
    (
        VulnerabilityCategory.HARDCODED_SECRET,
        (
            "hardcoded-secret",
            "hardcoded_password",
            "hardcoded-password",
            "hardcoded-credential",
            "hardcoded_credential",
            "secret-detected",
            "aws-access-key",
            "private-key",
            "api-key",
        ),
    ),
    (
        VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
        (
            "weak-crypto",
            "weak_crypto",
            "weak-hash",
            "weak_hash",
            "insecure-hash",
            "md5",
            "sha1",
            "crypto",
        ),
    ),
    (
        VulnerabilityCategory.INSECURE_TLS,
        (
            "insecure-tls",
            "insecure_tls",
            "tls-verification",
            "ssl-verification",
            "certificate-validation",
            "rejectunauthorized",
            "verify-false",
            "unverified-context",
        ),
    ),
    (
        VulnerabilityCategory.XXE,
        (
            "xxe",
            "xml-external-entity",
            "xml_external_entity",
            "external-entity",
        ),
    ),
    (
        VulnerabilityCategory.SSRF,
        ("ssrf", "server-side-request-forgery", "server_side_request_forgery"),
    ),
    (
        VulnerabilityCategory.OPEN_REDIRECT,
        ("open-redirect", "open_redirect", "unvalidated-redirect"),
    ),
    (
        VulnerabilityCategory.CSRF,
        ("csrf", "cross-site-request-forgery", "cross_site_request_forgery"),
    ),
    (
        VulnerabilityCategory.AUTH_BYPASS,
        (
            "auth-bypass",
            "auth_bypass",
            "authentication-bypass",
            "authorization-bypass",
            "missing-auth",
            "missing-authentication",
        ),
    ),
    (
        VulnerabilityCategory.INPUT_VALIDATION,
        (
            "input-validation",
            "input_validation",
            "improper-input",
            "unvalidated-input",
        ),
    ),
)

_TAINT_CATEGORY: dict[str, VulnerabilityCategory] = {
    "sql_injection": VulnerabilityCategory.SQL_INJECTION,
    "command_injection": VulnerabilityCategory.COMMAND_INJECTION,
    "xss": VulnerabilityCategory.XSS,
    "path_traversal": VulnerabilityCategory.PATH_TRAVERSAL,
    "unsafe_deserialization": VulnerabilityCategory.UNSAFE_DESERIALIZATION,
}


@dataclass(frozen=True, slots=True)
class Classification:
    """The selected category/CWE and the evidence behind the choice."""

    category: VulnerabilityCategory
    cwe: str | None
    cwe_support: tuple[CweSupport, ...] = ()
    conflicts: tuple[str, ...] = ()
    rationale: tuple[str, ...] = ()

    @property
    def classified(self) -> bool:
        return self.category.is_classified and self.cwe is not None


def category_for_cwe(value: object) -> VulnerabilityCategory | None:
    cwe = normalize_cwe(value)
    return _CWE_TO_CATEGORY.get(cwe) if cwe is not None else None


def default_cwe(category: VulnerabilityCategory) -> str | None:
    info = CATEGORY_INFO.get(category)
    return info.default_cwe if info is not None else None


def category_for_taint(value: object) -> VulnerabilityCategory:
    return _TAINT_CATEGORY.get(str(value), VulnerabilityCategory.UNKNOWN)


def infer_category(*texts: object) -> VulnerabilityCategory:
    """Infer a category from stable rule identifiers, titles, and messages."""
    haystack = " ".join(str(text).lower() for text in texts if text)
    if not haystack:
        return VulnerabilityCategory.UNKNOWN
    for category, patterns in _CATEGORY_PATTERNS:
        if any(pattern in haystack for pattern in patterns):
            return category
    return VulnerabilityCategory.UNKNOWN


def classify_text(
    *,
    rule_id: str | None = None,
    message: str | None = None,
    title: str | None = None,
    cwes: Iterable[object] = (),
    category_hint: VulnerabilityCategory | None = None,
) -> Classification:
    """Classify one textual finding without consulting other evidence."""
    explicit = tuple(dict.fromkeys(filter(None, (normalize_cwe(value) for value in cwes))))
    category = category_hint if category_hint is not None else VulnerabilityCategory.UNKNOWN
    if category is VulnerabilityCategory.UNKNOWN:
        for cwe in explicit:
            mapped = category_for_cwe(cwe)
            if mapped is not None and mapped is not VulnerabilityCategory.INPUT_VALIDATION:
                category = mapped
                break
    if category is VulnerabilityCategory.UNKNOWN:
        category = infer_category(rule_id, title, message)
    if category is VulnerabilityCategory.UNKNOWN:
        for cwe in explicit:
            mapped = category_for_cwe(cwe)
            if mapped is not None:
                category = mapped
                break

    if category is VulnerabilityCategory.UNKNOWN:
        return Classification(
            category=category,
            cwe=None,
            rationale=("No supported vulnerability category could be inferred.",),
        )

    category_cwe = default_cwe(category)
    chosen = category_cwe
    for cwe in explicit:
        if category_for_cwe(cwe) is category:
            chosen = cwe
            break
    conflicts = tuple(
        f"{cwe} maps to {category_for_cwe(cwe).value}, not the selected "
        f"{category.value}; it was retained as supporting evidence."
        for cwe in explicit
        if category_for_cwe(cwe) not in {None, category, VulnerabilityCategory.INPUT_VALIDATION}
    )
    support = tuple(
        CweSupport(
            cwe=cwe,
            category=category_for_cwe(cwe) or category,
            support=1.0,
            sources=(rule_id or "classification",),
        )
        for cwe in dict.fromkeys((*explicit, *((chosen,) if chosen else ())))
    )
    return Classification(
        category=category,
        cwe=chosen,
        cwe_support=support,
        conflicts=conflicts,
        rationale=(f"Selected {category.value} from rule, message, and CWE metadata.",),
    )


def classify_evidence(evidence: Iterable[EvidenceItem]) -> Classification:
    """Select a category and CWE from the weighted supporting evidence.

    The selection is not a vote and not an average. Category support is the sum
    of effective evidence support, with evidence grouped by category. The
    primary CWE must either be the category's documented CWE or map to the
    selected category, so unrelated generic CWEs cannot override a specific
    classification.
    """
    items = tuple(evidence)
    if not items:
        return Classification(
            category=VulnerabilityCategory.UNKNOWN,
            cwe=None,
            rationale=("No evidence was available.",),
        )

    category_scores: dict[VulnerabilityCategory, float] = {}
    category_sources: dict[VulnerabilityCategory, list[str]] = {}
    explicit_cwes: dict[str, float] = {}
    cwe_categories: dict[str, VulnerabilityCategory] = {}
    cwe_sources: dict[str, list[str]] = {}
    conflicts: list[str] = []

    for item in items:
        if item.polarity.value != "supports":
            continue
        weight = max(item.effective_support, 0.0)
        proposed = item.category
        if proposed is VulnerabilityCategory.UNKNOWN and item.cwe:
            proposed = category_for_cwe(item.cwe) or VulnerabilityCategory.UNKNOWN
        if proposed is VulnerabilityCategory.UNKNOWN:
            proposed = infer_category(item.rule_id, item.title, item.detail)
        if proposed is VulnerabilityCategory.UNKNOWN:
            continue
        category_scores[proposed] = category_scores.get(proposed, 0.0) + weight
        category_sources.setdefault(proposed, []).append(item.source)
        if item.cwe:
            explicit_cwes[item.cwe] = explicit_cwes.get(item.cwe, 0.0) + weight
            mapped = category_for_cwe(item.cwe)
            if mapped is not None:
                cwe_categories[item.cwe] = mapped
            cwe_sources.setdefault(item.cwe, []).append(item.source)

    if not category_scores:
        return Classification(
            category=VulnerabilityCategory.UNKNOWN,
            cwe=None,
            rationale=("Evidence did not support any known vulnerability category.",),
        )

    precedence = {category: index for index, category in enumerate(CATEGORY_ORDER)}
    category = max(
        category_scores,
        key=lambda value: (
            category_scores[value],
            -precedence[value],
        ),
    )
    category_cwe = default_cwe(category)

    cwe_scores: dict[str, float] = {}
    for cwe, score in explicit_cwes.items():
        cwe_scores[cwe] = cwe_scores.get(cwe, 0.0) + score
        mapped = cwe_categories.get(cwe)
        if (
            mapped is not None
            and mapped is not category
            and mapped is not VulnerabilityCategory.INPUT_VALIDATION
        ):
            conflicts.append(
                f"{cwe} maps to {mapped.value}, but fusion selected "
                f"{category.value}; the CWE was retained as supporting evidence."
            )
    if category_cwe:
        category_weight = sum(category_scores.values()) * 0.35
        cwe_scores[category_cwe] = cwe_scores.get(category_cwe, 0.0) + category_weight
        cwe_sources.setdefault(category_cwe, []).extend(category_sources.get(category, []))

    eligible = {
        cwe: score
        for cwe, score in cwe_scores.items()
        if cwe == category_cwe
        or cwe_categories.get(cwe) in {category, None, VulnerabilityCategory.INPUT_VALIDATION}
    }
    chosen_cwe = category_cwe
    if eligible:
        chosen_cwe = max(
            eligible,
            key=lambda value: (
                eligible[value],
                value == category_cwe,
                value,
            ),
        )

    if chosen_cwe is None:
        return Classification(
            category=category,
            cwe=None,
            conflicts=tuple(dict.fromkeys(conflicts)),
            rationale=(f"Selected {category.value}, but no supported CWE mapping exists.",),
        )

    support: list[CweSupport] = []
    total = sum(cwe_scores.values()) or 1.0
    for cwe, score in sorted(cwe_scores.items(), key=lambda pair: (-pair[1], pair[0])):
        support.append(
            CweSupport(
                cwe=cwe,
                category=cwe_categories.get(cwe, category),
                support=min(1.0, score / total),
                sources=tuple(dict.fromkeys(cwe_sources.get(cwe, ()))),
            )
        )
    rationale = [f"Selected {category.value} with support {category_scores[category]:.2f}."]
    if chosen_cwe != category_cwe:
        rationale.append(
            f"Explicit CWE evidence selected {chosen_cwe} over the category default {category_cwe}."
        )
    return Classification(
        category=category,
        cwe=chosen_cwe,
        cwe_support=tuple(support),
        conflicts=tuple(dict.fromkeys(conflicts)),
        rationale=tuple(rationale),
    )


def category_confidence(*texts: object) -> VulnerabilityCategory:
    """Compatibility helper used by adapters that only have text metadata."""
    return infer_category(*texts)


def cwes_from_text(*texts: object) -> tuple[str, ...]:
    return extract_cwes(texts)


__all__ = [
    "CATEGORY_INFO",
    "CATEGORY_ORDER",
    "CategoryInfo",
    "Classification",
    "category_confidence",
    "category_for_cwe",
    "category_for_taint",
    "classify_evidence",
    "classify_text",
    "cwes_from_text",
    "default_cwe",
    "infer_category",
]

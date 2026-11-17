"""Tests for the controlled corpus used by real-model validation runs."""

from __future__ import annotations

import ast

import pytest

from craftsec.counterfactual.validation_corpus import (
    LABEL_TOKEN_CANDIDATES,
    build_prompt,
    build_validation_corpus,
    decode_label_tokens,
    split_roles,
)


def test_corpus_is_deterministic_balanced_and_unique() -> None:
    first = build_validation_corpus()
    second = build_validation_corpus()
    assert first == second
    assert len(first) == 72
    assert len({sample.sample_id for sample in first}) == len(first)

    evaluation, training = split_roles(first)
    assert len(evaluation) == 24
    assert len(training) == 48

    cwes = {sample.cwe for sample in first}
    assert len(cwes) == 6
    for cwe in cwes:
        rows = [sample for sample in evaluation if sample.cwe == cwe]
        assert len(rows) == 4
        assert sum(sample.label == "vulnerable" for sample in rows) == 2
        assert sum(sample.label == "secure" for sample in rows) == 2


def test_generated_samples_are_valid_python_and_lexically_distinct() -> None:
    samples = build_validation_corpus()
    for sample in samples:
        ast.parse(sample.code)
        assert sample.prompt.startswith("Review the following Python code")
        assert sample.code.rstrip() in sample.prompt
        assert sample.prompt.endswith("Answer:")

    for cwe in {sample.cwe for sample in samples}:
        for label in {"vulnerable", "secure"}:
            codes = {
                sample.code for sample in samples if sample.cwe == cwe and sample.label == label
            }
            assert len(codes) == 6


def test_corpus_rejects_invalid_variant_counts_and_empty_code() -> None:
    with pytest.raises(ValueError, match="more variants"):
        build_validation_corpus(eval_variants=4, train_variants=4)
    with pytest.raises(ValueError, match="eval_variants"):
        build_validation_corpus(eval_variants=0)
    with pytest.raises(ValueError, match="code must not be empty"):
        build_prompt("   ")


class _FakeTokenizer:
    def __init__(self, multi: set[str]) -> None:
        self.multi = multi
        self.vocabulary = {
            text: index for index, pair in enumerate(LABEL_TOKEN_CANDIDATES) for text in pair
        }

    def encode(self, text: str, *, add_special_tokens: bool = False) -> list[int]:
        assert add_special_tokens is False
        token = self.vocabulary[text]
        return [token, token + 1_000] if text in self.multi else [token]


def test_label_token_resolution_requires_single_token_labels() -> None:
    tokenizer = _FakeTokenizer(multi={" A", "A", " yes"})
    first, second, first_text, second_text = decode_label_tokens(tokenizer)
    assert (first_text, second_text) == (" unsafe", " safe")
    assert first in tokenizer.encode(first_text)
    assert second in tokenizer.encode(second_text)

    with pytest.raises(ValueError, match="single tokens"):
        decode_label_tokens(
            _FakeTokenizer(multi={text for pair in LABEL_TOKEN_CANDIDATES for text in pair})
        )

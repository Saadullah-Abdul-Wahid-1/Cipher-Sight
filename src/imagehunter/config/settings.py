"""Settings loading and validation.

Defaults ship inside the package (default_settings.json) so they work after
installation. A user file may override any known key; unknown keys are an error
so that typos are caught instead of silently ignored.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, fields
from importlib import resources
from pathlib import Path

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


class ConfigError(ValueError):
    """Settings file is unreadable, has unknown keys, or has invalid values."""


@dataclass(frozen=True)
class Settings:
    schema_version: int = 1
    max_input_bytes: int = 200 * 1024 * 1024
    min_string_length: int = 4
    max_strings: int = 500
    tool_timeout_seconds: float = 30.0
    tool_output_cap_bytes: int = 1024 * 1024
    workspace_root: str = "workspace"
    log_level: str = "WARNING"
    stego_max_bytes: int = 65536          # bytes decoded per LSB experiment
    max_pixels: int = 20_000_000          # larger images skip pixel analysis
    lsb_max_channels: int = 1             # 1 = single channel; 2 or 3 = interleaved channel streams (slower)
    lsb_unknown_prefix_leads: bool = True  # detect flag-like text with prefixes not in the configured list
    lsb_repeating_key_max: int = 3         # repeating XOR key length searched with known-prefix cribs; 0 disables, max 4
    flag_prefixes: tuple = ("THM", "CTF", "FLAG", "flag", "HTB", "picoCTF")
    metadata_max_bytes: int = 65536       # text/profile blocks above this are reported as oversized
    smart_words_enabled: bool = True
    investigation_mode: str = "standard"       # quick | standard | deep | auto
    investigation_time_budget_seconds: float = 0.0   # 0 = no time limit; analyzers stop being started after it
    decoding_enabled: bool = True
    vision_analysis_enabled: bool = False  # optional OCR/QR; opt in to avoid slow external OCR by default
    decoding_max_depth: int = 3            # decode steps per chain
    decoding_max_nodes: int = 2000         # artifacts created per scan
    decoding_max_output: int = 65536       # bytes per decoded artifact
    decoding_max_seeds: int = 1000         # encoded-looking strings used as starting points
    decoding_xor_budget: int = 5_000_000   # bytes tested by known-prefix XOR per scan
    smart_min_token_length: int = 3
    smart_max_token_length: int = 64
    smart_max_ngram_words: int = 5
    smart_min_candidate_score: int = 20
    smart_max_candidates: int = 10000
    smart_max_variants: int = 24
    smart_enable_leetspeak: bool = True
    smart_enable_separators: bool = True
    smart_reverse_mode: str = "clue_only"          # off | clue_only | on
    smart_include_low_priority: bool = True
    smart_stopword_language: str = "en"
    smart_max_source_chars: int = 2_000_000
    smart_weights: dict = field(default_factory=lambda: {
        "clue_strong": 30, "clue_medium": 20, "clue_weak": 10, "clue_context": 5,
        "rarity": 20, "corroboration": 15, "phrase_near_clue": 15, "caps_digits": 10, "date_near_clue": 10,
        "transform_penalty": 10})
    expected_phrases: tuple = ()          # analyst-defined clue phrases; empty = none searched

    def validate(self) -> None:
        def is_int(v):
            return isinstance(v, int) and not isinstance(v, bool)

        def is_num(v):
            return isinstance(v, (int, float)) and not isinstance(v, bool)

        checks = [
            (self.schema_version == 1, "schema_version must be 1"),
            (is_int(self.max_input_bytes) and self.max_input_bytes > 0, "max_input_bytes must be a positive integer"),
            (is_int(self.min_string_length) and self.min_string_length >= 1, "min_string_length must be >= 1"),
            (is_int(self.max_strings) and self.max_strings >= 1, "max_strings must be >= 1"),
            (is_num(self.tool_timeout_seconds) and self.tool_timeout_seconds > 0, "tool_timeout_seconds must be > 0"),
            (is_int(self.tool_output_cap_bytes) and self.tool_output_cap_bytes > 0, "tool_output_cap_bytes must be > 0"),
            (isinstance(self.workspace_root, str) and self.workspace_root.strip() != "", "workspace_root must be a non-empty string"),
            (self.log_level in LOG_LEVELS, f"log_level must be one of {', '.join(LOG_LEVELS)}"),
            (is_int(self.stego_max_bytes) and self.stego_max_bytes >= 4, "stego_max_bytes must be >= 4"),
            (is_int(self.lsb_max_channels) and 1 <= self.lsb_max_channels <= 3,
             "lsb_max_channels must be 1, 2 or 3"),
            (isinstance(self.lsb_unknown_prefix_leads, bool), "lsb_unknown_prefix_leads must be true or false"),
            (is_int(self.lsb_repeating_key_max) and 0 <= self.lsb_repeating_key_max <= 4,
             "lsb_repeating_key_max must be between 0 and 4"),
            (is_int(self.max_pixels) and self.max_pixels > 0, "max_pixels must be > 0"),
            (is_int(self.smart_min_token_length) and 1 <= self.smart_min_token_length <= self.smart_max_token_length,
             "smart_min_token_length must be between 1 and smart_max_token_length"),
            (is_int(self.smart_max_token_length) and 1 <= self.smart_max_token_length <= 256,
             "smart_max_token_length must be between 1 and 256"),
            (is_int(self.smart_max_ngram_words) and 1 <= self.smart_max_ngram_words <= 8,
             "smart_max_ngram_words must be between 1 and 8"),
            (is_int(self.smart_min_candidate_score) and 0 <= self.smart_min_candidate_score <= 100,
             "smart_min_candidate_score must be between 0 and 100"),
            (is_int(self.smart_max_candidates) and 1 <= self.smart_max_candidates <= 1_000_000,
             "smart_max_candidates must be between 1 and 1000000"),
            (is_int(self.smart_max_variants) and 0 <= self.smart_max_variants <= 64,
             "smart_max_variants must be between 0 and 64"),
            (self.smart_reverse_mode in ("off", "clue_only", "on"),
             "smart_reverse_mode must be off, clue_only or on"),
            (self.smart_stopword_language == "en",
             "smart_stopword_language must be 'en' (the only bundled list)"),
            (is_int(self.smart_max_source_chars) and self.smart_max_source_chars >= 1000,
             "smart_max_source_chars must be >= 1000"),
            (isinstance(self.smart_weights, dict)
             and set(self.smart_weights) == {"clue_strong", "clue_medium", "clue_weak", "clue_context", "rarity",
                                            "corroboration", "phrase_near_clue", "caps_digits", "date_near_clue",
                                            "transform_penalty"}
             and all(is_int(v) and 0 <= v <= 100 for v in self.smart_weights.values()),
             "smart_weights must contain exactly the ten weight keys, each an integer 0-100"),
            (isinstance(self.decoding_enabled, bool), "decoding_enabled must be true or false"),
            (isinstance(self.vision_analysis_enabled, bool), "vision_analysis_enabled must be true or false"),
            (self.investigation_mode in ("quick", "standard", "deep", "auto"),
             "investigation_mode must be quick, standard, deep or auto"),
            (isinstance(self.investigation_time_budget_seconds, (int, float))
             and not isinstance(self.investigation_time_budget_seconds, bool)
             and self.investigation_time_budget_seconds >= 0,
             "investigation_time_budget_seconds must be 0 or more"),
            (is_int(self.decoding_max_depth) and 1 <= self.decoding_max_depth <= 6,
             "decoding_max_depth must be between 1 and 6"),
            (is_int(self.decoding_max_nodes) and 10 <= self.decoding_max_nodes <= 200000,
             "decoding_max_nodes must be between 10 and 200000"),
            (is_int(self.decoding_max_output) and 1024 <= self.decoding_max_output <= 16777216,
             "decoding_max_output must be between 1024 and 16777216"),
            (is_int(self.decoding_max_seeds) and 1 <= self.decoding_max_seeds <= 100000,
             "decoding_max_seeds must be between 1 and 100000"),
            (is_int(self.decoding_xor_budget) and 0 <= self.decoding_xor_budget <= 500000000,
             "decoding_xor_budget must be between 0 and 500000000"),
            (is_int(self.metadata_max_bytes) and self.metadata_max_bytes >= 1024,
             "metadata_max_bytes must be >= 1024"),
            (isinstance(self.expected_phrases, (list, tuple))
             and all(isinstance(x, str) and 1 <= len(x) <= 200 for x in self.expected_phrases),
             "expected_phrases must be a list of strings, 1-200 characters each"),
            (isinstance(self.flag_prefixes, (list, tuple)) and len(self.flag_prefixes) > 0
             and all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_]{1,32}", x) for x in self.flag_prefixes),
             "flag_prefixes must be a non-empty list of 1-32 character names (letters, digits, underscore)"),
        ]
        for ok, message in checks:
            if not ok:
                raise ConfigError(message)


def _read_defaults() -> dict:
    text = (resources.files("imagehunter.config") / "default_settings.json").read_text(encoding="utf-8")
    return json.loads(text)


def load_settings(user_path: str | Path | None = None) -> Settings:
    raw = _read_defaults()
    if user_path is not None:
        try:
            user = json.loads(Path(user_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read settings file {user_path}: {exc}") from exc
        if not isinstance(user, dict):
            raise ConfigError("settings file must contain a JSON object")
        raw.update(user)

    known = {f.name for f in fields(Settings)}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(f"unknown settings key(s): {', '.join(unknown)}")
    if isinstance(raw.get("flag_prefixes"), list):
        raw["flag_prefixes"] = tuple(raw["flag_prefixes"])
    if isinstance(raw.get("expected_phrases"), list):
        raw["expected_phrases"] = tuple(raw["expected_phrases"])
    settings = Settings(**raw)
    settings.validate()
    return settings

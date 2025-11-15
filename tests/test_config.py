"""Defence presets and settings (spec 6)."""

from __future__ import annotations

import dataclasses

import pytest

from doorman import config


class TestPresets:
    def test_all_five_presets_exist(self):
        assert set(config.PRESETS) == {
            "none",
            "prompt_only",
            "isolation_only",
            "full_minus_classifier",
            "full",
        }

    def test_none_is_genuinely_undefended(self):
        """Spec 21.8: every layer off, or the baseline is not a baseline."""
        cfg = config.preset("none")
        layers = {k: v for k, v in cfg.as_dict().items() if k != "name"}
        assert not any(layers.values()), layers

    def test_prompt_only_differs_from_none_by_exactly_one_flag(self):
        none, prompt = config.preset("none").as_dict(), config.preset("prompt_only").as_dict()
        differing = [k for k in none if k != "name" and none[k] != prompt[k]]
        assert differing == ["polite_prompt"]

    def test_full_enables_every_layer(self):
        cfg = config.preset("full").as_dict()
        assert all(v for k, v in cfg.items() if k != "name")

    def test_full_minus_classifier_differs_from_full_by_exactly_one_flag(self):
        full = config.preset("full").as_dict()
        minus = config.preset("full_minus_classifier").as_dict()
        differing = [k for k in full if k != "name" and full[k] != minus[k]]
        assert differing == ["classifier"]

    def test_preset_names_match_their_keys(self):
        for name, cfg in config.PRESETS.items():
            assert cfg.name == name

    def test_presets_are_frozen(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            config.preset("full").classifier = False

    def test_unknown_preset_raises(self):
        with pytest.raises(KeyError, match="unknown config"):
            config.preset("mostly")


class TestSettings:
    def test_defaults_match_the_pinned_models(self, monkeypatch):
        for key in ("DOORMAN_AGENT_MODEL", "DOORMAN_READER_MODEL", "DOORMAN_TEMPERATURE"):
            monkeypatch.delenv(key, raising=False)
        settings = config.load_settings(dotenv=False)
        assert settings.agent_model == "claude-sonnet-5"
        assert settings.reader_model == "claude-haiku-4-5"
        assert settings.temperature == 0.0

    def test_thresholds_match_the_spec(self, monkeypatch):
        for key in list(config.os.environ):
            if key.startswith("DOORMAN_"):
                monkeypatch.delenv(key, raising=False)
        settings = config.load_settings(dotenv=False)
        assert settings.classifier_threshold == 0.85
        assert settings.classifier_chunk_tokens == 400
        assert settings.classifier_chunk_overlap == 50
        assert settings.hidden_font_pt == 4.0
        assert settings.near_white_luminance == 0.93
        assert settings.max_turns_per_phase == 4
        assert settings.max_turns_single_call == 10

    def test_environment_overrides_defaults(self, monkeypatch):
        monkeypatch.setenv("DOORMAN_AGENT_MODEL", "some-other-model")
        assert config.load_settings(dotenv=False).agent_model == "some-other-model"


class TestDotenv:
    def test_loads_pairs_and_ignores_comments(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DOORMAN_AGENT_MODEL", raising=False)
        env = tmp_path / ".env"
        env.write_text('# a comment\nDOORMAN_AGENT_MODEL="from-dotenv"\n\nBARE\n')
        config.load_dotenv(env)
        assert config.os.environ["DOORMAN_AGENT_MODEL"] == "from-dotenv"

    def test_existing_environment_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DOORMAN_AGENT_MODEL", "from-env")
        env = tmp_path / ".env"
        env.write_text("DOORMAN_AGENT_MODEL=from-dotenv\n")
        config.load_dotenv(env)
        assert config.os.environ["DOORMAN_AGENT_MODEL"] == "from-env"

    def test_missing_file_is_not_an_error(self, tmp_path):
        config.load_dotenv(tmp_path / "nope.env")

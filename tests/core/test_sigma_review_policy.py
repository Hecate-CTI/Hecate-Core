"""Rejected proposals cannot cross the generation or artifact-writing boundary."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from hecate_agent import api
from hecate_agent.agents.base import AgentResult
from hecate_agent.agents.llm.sigma.models import SigmaGenerationOutput, SigmaRule
from hecate_agent.core.sigma_review_policy import review_rejection_reason


def document(verdict="reject"):
    return {"title":"Python connection", "logsource":{"category":"network_connection","product":"linux"},
            "detection":{"selection":{"Image|endswith":r"\python.exe"},"condition":"selection"},
            "hecate_review":{"verdict":verdict,"issues":["Windows executable path on Linux"]}}


@pytest.mark.parametrize("verdict", ["reject", "REJECT", " Reject "])
def test_rejection_does_not_require_a_source_quote(verdict):
    assert review_rejection_reason(document(verdict)) == "Windows executable path on Linux"


@pytest.mark.parametrize("review", [None, {}, {"verdict":"keep"}, {"verdict":"revise"}, {"verdict":"remediated"}])
def test_other_review_states_are_not_rejections(review):
    doc = document()
    doc["hecate_review"] = review
    assert review_rejection_reason(doc) is None


def test_api_cannot_write_a_rejected_rule_even_if_generator_reports_success(tmp_path, monkeypatch):
    output = SigmaGenerationOutput(rules=[SigmaRule("network_connection","Broken Python rule",yaml.safe_dump(document()))])
    monkeypatch.setattr(api,"SigmaGeneratorAgent",lambda **kwargs: SimpleNamespace(execute=lambda *_: AgentResult(True,output)))
    transpile=Mock()
    monkeypatch.setattr(api,"transpile_sigma_rule",transpile)
    result, files, metadata=api.generate_sigma_with_metrics({"hypothesis":"Source-backed Python activity"},out_dir=tmp_path / "queries")
    assert not metadata["success"]
    assert not result.rules and not files
    assert any("Windows executable path" in reason for reason in result.rejected)
    assert not (tmp_path / "queries").exists()
    transpile.assert_not_called()


def test_api_mixed_result_only_writes_accepted_artifacts(tmp_path, monkeypatch):
    output=SigmaGenerationOutput(rules=[
        SigmaRule("network_connection","Rejected",yaml.safe_dump(document())),
        SigmaRule("network_connection","Accepted",yaml.safe_dump(document("keep"))),
    ])
    monkeypatch.setattr(api,"SigmaGeneratorAgent",lambda **kwargs: SimpleNamespace(execute=lambda *_: AgentResult(True,output)))
    monkeypatch.setattr(api,"transpile_sigma_rule",lambda *_:{})
    result,files,metadata=api.generate_sigma_with_metrics({"hypothesis":"Source-backed Python activity"},out_dir=tmp_path)
    assert metadata["success"]
    assert [rule.title for rule in result.rules] == ["Accepted"]
    assert [path.name for path in files] == ["network_connection__accepted.yml"]
    assert len(list(tmp_path.glob("*.yml"))) == 1

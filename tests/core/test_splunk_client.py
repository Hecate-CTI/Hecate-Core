"""Search failures must never be rendered as empty telemetry coverage."""
import importlib
from unittest.mock import MagicMock

import pytest

pytest.importorskip("requests", reason="Splunk optional dependency not installed")
from click.testing import CliRunner  # noqa: E402
from hecate_agent.core.splunk_client import SplunkClient  # noqa: E402


def client_with_response(monkeypatch, payload):
    client = SplunkClient("localhost")
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = payload
    request = MagicMock(return_value=response)
    monkeypatch.setattr(client.session, "request", request)
    return client, request


@pytest.mark.parametrize("query", [
    "| tstats count WHERE index=main", "  | makeresults | stats count",
    "| rest /services/data/indexes | stats count", "search index=main | stats count",
    "index=main | stats count",
])
@pytest.mark.parametrize("async_job", [False, True])
def test_generating_commands_are_preserved_and_event_searches_still_work(monkeypatch, query, async_job):
    client, request = client_with_response(monkeypatch, {"sid":"job", "results":[{"count":"0"}]})
    if async_job:
        assert client.create_search_job(query) == "job"
    else:
        assert client.search(query) == [{"count":"0"}]
    submitted = request.call_args.kwargs['data']['search']
    if query.lstrip().startswith('|'):
        assert submitted == query.lstrip()
    else:
        assert submitted == 'search index=main | stats count'


@pytest.mark.parametrize("kind", ["ERROR", "FATAL"])
def test_http_200_search_error_is_not_an_empty_result(monkeypatch, kind):
    client, _ = client_with_response(monkeypatch, {"messages":[{
        "type":kind,"text":"This command must be the first command of a search."}],"results":[]})
    with pytest.raises(RuntimeError, match="first command"):
        client.search("| tstats count WHERE index=main")


def test_warnings_and_a_real_zero_count_remain_valid(monkeypatch):
    client, _ = client_with_response(monkeypatch, {"messages":[{"type":"WARN","text":"Informational limit"}],
                                                "results":[{"count":"0"}]})
    assert client.search('index=main | stats count') == [{"count":"0"}]


def test_failed_async_job_does_not_return_results(monkeypatch):
    client, _ = client_with_response(monkeypatch, {"entry":[{"content":{"dispatchState":"FAILED","isDone":True}}]})
    with pytest.raises(RuntimeError, match="failed"):
        client.wait_for_search_job('job', poll_interval=1, max_wait=2)


def test_cli_exits_unsuccessfully_on_server_search_error(monkeypatch):
    client, _ = client_with_response(monkeypatch, {"messages":[{"type":"FATAL","text":"Invalid search command"}]})
    command = importlib.import_module('hecate_agent.commands.splunk')
    monkeypatch.setattr(command, 'get_client', lambda *args: client)
    result = CliRunner().invoke(command.splunk, ['search','| not_a_real_command','--earliest=-7d','--latest=now','--count=1'])
    assert result.exit_code != 0
    assert 'No results found' not in result.output


def test_whitespace_cannot_become_an_unfiltered_event_search(monkeypatch):
    client, request = client_with_response(monkeypatch, {})
    with pytest.raises(ValueError, match="Empty"):
        client.search(" \n\t ")
    request.assert_not_called()

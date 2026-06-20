import pytest

from spellbook.mcp import servers
from spellbook.mcp.servers import context_sources, mcp_servers


WIZ_VARS = ["WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET"]
CONTEXT_VARS = ["GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TOKEN", "NOTION_API_KEY",
                "NOTION_TOKEN", "LINEAR_API_KEY"]


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    for var in WIZ_VARS + CONTEXT_VARS:
        monkeypatch.delenv(var, raising=False)


def test_empty_when_nothing_configured():
    assert mcp_servers() == {}
    assert context_sources() == []


def test_wiz_only():
    import os
    os.environ["WIZ_CLIENT_ID"] = "id"
    os.environ["WIZ_CLIENT_SECRET"] = "secret"
    try:
        assert set(mcp_servers()) == {"wiz"}
        assert context_sources() == []
    finally:
        del os.environ["WIZ_CLIENT_ID"], os.environ["WIZ_CLIENT_SECRET"]


def test_github_context(monkeypatch):
    monkeypatch.setenv("GITHUB_PERSONAL_ACCESS_TOKEN", "ghp_x")
    servers_cfg = mcp_servers()
    assert "github" in servers_cfg
    assert servers_cfg["github"]["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"] == "ghp_x"
    assert context_sources() == ["github"]


def test_all_context_sources(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("NOTION_API_KEY", "notion_x")
    monkeypatch.setenv("LINEAR_API_KEY", "lin_x")
    assert context_sources() == ["github", "notion", "linear"]
    assert set(mcp_servers()) == {"github", "notion", "linear"}


def test_package_override(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("GITHUB_MCP_PACKAGE", "custom-github-mcp")
    assert mcp_servers()["github"]["args"][-1] == "custom-github-mcp"

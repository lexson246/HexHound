"""设置持久化、认证身份解析与本机控制面的回归测试（全部本地，不发真实请求）。

这些用例对应四个**已确认**的问题（都能在旧代码上复现）：

* P0-1 普通保存会把已保存的密钥清空（`_save_settings` 从 DEFAULTS 重建字典）；
* P0-2 非法认证 JSON 静默变成匿名身份（配置错误被写成"访问控制缺陷"）；
* P0-3 见 `tests/test_xss_verify.py`（浏览器验证把普通弹窗当成 XSS 执行）；
* P0-4 `/api/providers` 回传明文密钥 + 本机接口无 CSRF 防护。

约定：只用临时配置目录与假密钥（`sk-fake-*`），绝不读写真实 `.env` 或真实密钥。
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import gui  # noqa: E402


@pytest.fixture()
def settings_file(monkeypatch, tmp_path) -> Path:
    """把设置文件指向临时目录（绝不落到用户真实配置上）。"""
    path = tmp_path / "settings.json"
    monkeypatch.setattr(gui, "SETTINGS_PATH", path)
    return path


def _write_settings(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _read_settings(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- P0-1 保存


def test_ordinary_save_keeps_saved_provider_keys(settings_file: Path) -> None:
    """普通保存（表单里根本没有 provider_keys 字段）不得清空已保存的密钥。

    旧行为：`_save_settings` 用 `DEFAULTS` 重建整个字典，于是任何一次
    "保存配置"都会把 `provider_keys` 打回 `{}`——用户密钥**静默消失**。
    """
    _write_settings(
        settings_file,
        {"provider": "deepseek", "provider_keys": json.dumps({"deepseek": "sk-fake-0001"})},
    )
    gui._save_settings({"target": "http://127.0.0.1:5000", "mode": "blackbox"})

    assert gui._provider_keys() == {"deepseek": "sk-fake-0001"}
    stored = _read_settings(settings_file)
    assert stored["target"] == "http://127.0.0.1:5000"
    assert json.loads(stored["provider_keys"]) == {"deepseek": "sk-fake-0001"}


def test_explicit_none_clears_a_field_to_its_default(settings_file: Path) -> None:
    """`None` 是"显式清空"：密钥要能真的删掉，而不是永远删不掉。"""
    _write_settings(
        settings_file,
        {"provider_keys": json.dumps({"deepseek": "sk-fake-0001"}), "target": "http://x/"},
    )
    gui._save_settings({"provider_keys": None, "target": None})

    assert gui._provider_keys() == {}
    stored = _read_settings(settings_file)
    assert stored["provider_keys"] == gui.DEFAULTS["provider_keys"]
    assert stored["target"] == gui.DEFAULTS["target"]


def test_role_model_fields_round_trip(settings_file: Path) -> None:
    """按角色的模型字段沿用同一套"未提交就不动"的语义。"""
    gui._save_settings({"role_model_verify": "qwen-max"})
    assert _read_settings(settings_file)["role_model_verify"] == "qwen-max"
    # 其它一次保存不带这个字段 → 不能被清掉
    gui._save_settings({"target": "http://127.0.0.1:5000"})
    assert _read_settings(settings_file)["role_model_verify"] == "qwen-max"
    # 显式清空
    gui._save_settings({"role_model_verify": ""})
    assert _read_settings(settings_file)["role_model_verify"] == ""


def test_unknown_fields_are_not_persisted(settings_file: Path) -> None:
    """白名单之外的表单字段不落盘（界面字段改名不该悄悄扩配置面）。"""
    gui._save_settings({"target": "http://127.0.0.1:5000", "not_a_setting": "x"})
    assert "not_a_setting" not in _read_settings(settings_file)


def test_atomic_write_leaves_no_temp_files(settings_file: Path) -> None:
    """原子写：成功后同目录不残留临时文件。"""
    gui._save_settings({"target": "http://127.0.0.1:5000"})
    leftovers = [p.name for p in settings_file.parent.iterdir() if p.name != settings_file.name]
    assert leftovers == []


def test_concurrent_saves_do_not_lose_each_others_fields(settings_file: Path) -> None:
    """并发保存串行化：两个字段都被保留（旧代码里后写会清掉先写）。"""
    _write_settings(settings_file, {"provider_keys": json.dumps({"deepseek": "sk-fake-0001"})})

    def save_target() -> None:
        gui._save_settings({"target": "http://127.0.0.1:5000"})

    def save_model() -> None:
        gui._save_settings({"model": "fake-model"})

    threads = [threading.Thread(target=save_target) for _ in range(10)]
    threads += [threading.Thread(target=save_model) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    stored = _read_settings(settings_file)
    assert stored["model"] == "fake-model"
    assert stored["target"] == "http://127.0.0.1:5000"
    assert gui._provider_keys() == {"deepseek": "sk-fake-0001"}


# ------------------------------------------------------- P0-2 认证身份解析


def test_valid_auth_profile_is_parsed() -> None:
    assert gui._parse_auth_profile('{"Cookie": "a=1"}') == {"Cookie": "a=1"}


def test_blank_auth_profile_means_anonymous() -> None:
    """留空 = 明确的匿名身份（不是错误）。"""
    assert gui._parse_auth_profile("") == {}
    assert gui._parse_auth_profile("   ") == {}
    assert gui._parse_auth_profile(None) == {}


@pytest.mark.parametrize(
    "raw",
    [
        "{not json",
        '["a"]',
        '"text"',
        "123",
        '{"Cookie": 123}',
        '{"Cookie": ""}',
        '{"": "value"}',
    ],
)
def test_invalid_auth_profile_raises_instead_of_becoming_anonymous(raw: str) -> None:
    """非法配置必须报错——**不能**静默降级成匿名。

    这是最危险的一类错误方向：配置写错会变成"这些接口匿名也能读"，
    报告里看起来就是访问控制缺陷。
    """
    with pytest.raises(ValueError):
        gui._parse_auth_profile(raw, label="身份 A 的 Cookie/Token")


def test_auth_error_never_echoes_the_secret() -> None:
    """报错只给字段名/类型，绝不回显值（值就是 Cookie/Token）。"""
    secret = "session=SUPERSECRETVALUE"
    with pytest.raises(ValueError) as excinfo:
        gui._parse_auth_profile('{"Cookie": 42, "X": "' + secret + '"}')
    assert secret not in str(excinfo.value)
    assert "Cookie" in str(excinfo.value)
    assert "int" in str(excinfo.value)


def test_auth_profiles_are_labelled_per_identity() -> None:
    profiles = gui._parse_auth_profiles({"auth_a": '{"Cookie": "a=1"}'})
    assert profiles["A"] == {"Cookie": "a=1"}
    assert profiles["B"] == {}
    with pytest.raises(ValueError) as excinfo:
        gui._parse_auth_profiles({"auth_a": "{bad", "auth_b": ""})
    assert "身份 A" in str(excinfo.value)


def test_validate_run_settings_wraps_the_error_for_the_ui() -> None:
    with pytest.raises(ValueError) as excinfo:
        gui._validate_run_settings({"auth_b": "{bad"})
    message = str(excinfo.value)
    assert "已阻止启动" in message
    assert "身份 B" in message


# ------------------------------------------------- P0-4 本机控制面与密钥暴露


@pytest.fixture()
def app(monkeypatch, settings_file: Path):
    """一份隔离的 GUI 应用（临时设置文件、干净状态）。"""
    monkeypatch.setattr(gui, "STATE", gui.RunState())
    application = gui.create_app()
    application.config.update(TESTING=True)
    return application


@pytest.fixture()
def token(app) -> str:
    return app.config["HEXHOUND_LOCAL_TOKEN"]


@pytest.fixture()
def client(app):
    return app.test_client()


def _auth(token: str) -> dict:
    return {gui.TOKEN_HEADER: token}


def test_providers_endpoint_never_returns_plaintext_keys(app, token, client) -> None:
    """`/api/providers` 只回掩码与"是否已保存"，绝不回明文密钥。"""
    gui._save_settings({"provider_keys": json.dumps({"deepseek": "sk-fake-0001"})})
    payload = client.get("/api/providers", headers=_auth(token)).get_json()

    assert "keys" not in payload
    assert payload["keys_saved"] == {"deepseek": True}
    assert payload["keys_masked"]["deepseek"].endswith("0001")
    assert "sk-fake-0001" not in json.dumps(payload, ensure_ascii=False)


def test_saving_the_displayed_mask_is_rejected(client, token) -> None:
    """把界面回显的掩码当密钥存回来必须被拒。

    否则之后每次请求都拿着一个必然失败的假密钥，而界面还显示"已保存"。
    """
    gui._save_settings({"provider_keys": json.dumps({"deepseek": "sk-fake-0001"})})
    mask = gui.mask_key("sk-fake-0001")

    response = client.post(
        "/api/provider_key", json={"provider": "deepseek", "api_key": mask}, headers=_auth(token)
    )
    assert response.status_code == 400
    assert "掩码" in response.get_json()["error"]
    assert gui._provider_keys()["deepseek"] == "sk-fake-0001"


def test_state_changing_endpoints_require_the_session_token(client) -> None:
    """本机接口不是"谁都能调"：没有会话令牌一律拒绝（防 CSRF）。"""
    assert client.post("/api/stop").status_code == 403
    assert client.post("/api/save", json={"target": "http://127.0.0.1:5000"}).status_code == 403
    assert client.post("/api/provider_key", json={"provider": "x", "api_key": "y"}).status_code == 403


def test_foreign_host_and_origin_are_rejected(client) -> None:
    """DNS rebinding / 跨站来源：Host 与 Origin 都必须是本机。"""
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 403
    assert client.get("/api/providers", headers={"Host": "evil.example"}).status_code == 403
    assert (
        client.get("/api/status", headers={"Origin": "http://evil.example"}).status_code == 403
    )
    assert client.get("/api/status").status_code == 200


def test_provider_error_text_is_scrubbed(token, client, monkeypatch) -> None:
    """提供商报错经常原样回显密钥——展示前必须打码。"""

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def test_connection(self):
            raise RuntimeError(
                "Incorrect API key provided: sk-fake-0001. You can find your API key at ..."
            )

    monkeypatch.setattr(gui, "LLMClient", FakeClient)
    response = client.post(
        "/api/provider_test",
        json={"provider": "deepseek", "model": "deepseek-chat", "api_key": "sk-fake-0001"},
        headers=_auth(token),
    )
    assert response.status_code == 500
    error = response.get_json()["error"]
    assert "sk-fake-0001" not in error
    assert "sk-fak" in error  # 掩码保留了可辨识的前缀


def test_scrub_secrets_handles_unknown_keys_too() -> None:
    """刚粘贴、还没保存的密钥也要打码（按形态兜底）。"""
    assert "sk-abcdefghijkl" not in gui._scrub_secrets("bad key sk-abcdefghijkl rejected")
    assert "***" in gui._scrub_secrets("Authorization: Bearer abcdefghijklmnop")


def test_invalid_auth_blocks_the_run_before_it_starts(app, client, token) -> None:
    """认证配置错误 → 400 + 明确原因，且**不启动**任务（不静默变匿名）。"""
    response = client.post(
        "/api/run",
        json={"auth_a": "{bad json", "target": "http://127.0.0.1:5000"},
        headers=_auth(token),
    )
    assert response.status_code == 400
    assert "已阻止启动" in response.get_json()["error"]
    snapshot = gui.STATE.snapshot()
    assert snapshot["status"] == gui.STATUS_IDLE
    assert snapshot["running"] is False


def test_duplicate_run_is_refused_while_one_is_active(app, client, token) -> None:
    """已有任务在跑（或正在停止）时拒绝重复启动，避免两个审计线程互相污染。"""
    assert gui.STATE.try_begin() is True
    try:
        response = client.post(
            "/api/run",
            json={"auth_a": "", "target": "http://127.0.0.1:5000"},
            headers=_auth(token),
        )
        assert response.status_code == 409
        assert "已有审计任务" in response.get_json()["error"]
    finally:
        gui.STATE.abort_begin()

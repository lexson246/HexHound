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
    assert _decoded_keys(stored["provider_keys"]) == {"deepseek": "sk-fake-0001"}


def _decoded_keys(stored_value: str) -> dict:
    """把落盘的 provider_keys 字段读回明文 dict（兼容加密与旧明文两种形态）。"""
    from hexhound import secretstore

    if secretstore.is_protected(stored_value):
        plain, error = secretstore.unprotect(stored_value)
        assert not error, error
        return json.loads(plain)
    return json.loads(stored_value)


def test_explicit_none_clears_a_field_to_its_default(settings_file: Path) -> None:
    """`None` 是"显式清空"：密钥要能真的删掉，而不是永远删不掉。"""
    _write_settings(
        settings_file,
        {"provider_keys": json.dumps({"deepseek": "sk-fake-0001"}), "target": "http://x/"},
    )
    gui._save_settings({"provider_keys": None, "target": None})

    assert gui._provider_keys() == {}
    stored = _read_settings(settings_file)
    # 清空后落盘的内容解出来必须是空字典（可能带加密外壳）
    assert _decoded_keys(stored["provider_keys"]) == {}
    assert stored["target"] == gui.DEFAULTS["target"]


def test_keys_are_not_stored_in_plaintext(settings_file: Path) -> None:
    """密钥落盘后，文件里**不能出现明文**（Windows 用 DPAPI 加密）。

    上一轮补掉了"密钥经 HTTP 回传浏览器"，但文件本身一直是明文——
    同步盘、备份、误发的截图都可能带上它。
    """
    gui._save_settings({"provider_keys": json.dumps({"deepseek": "sk-fake-0001"})})
    text = settings_file.read_text(encoding="utf-8")
    assert "sk-fake-0001" not in text
    from hexhound import secretstore

    available, _reason = secretstore.protection_available()
    if available:
        assert secretstore.is_protected(_read_settings(settings_file)["provider_keys"])
    # 无论哪种形态，读回来都必须是原值（加密不能丢数据）
    assert gui._provider_keys() == {"deepseek": "sk-fake-0001"}


def test_legacy_plaintext_is_migrated_without_losing_keys(settings_file: Path) -> None:
    """旧文件里的明文密钥要在下一次保存时自动迁移，且**一个都不能丢**。"""
    _write_settings(
        settings_file,
        {"provider_keys": json.dumps({"deepseek": "sk-fake-0001", "qwen": "sk-fake-0002"})},
    )
    assert gui._provider_keys() == {"deepseek": "sk-fake-0001", "qwen": "sk-fake-0002"}
    gui._save_settings({"target": "http://127.0.0.1:5000"})
    assert gui._provider_keys() == {"deepseek": "sk-fake-0001", "qwen": "sk-fake-0002"}
    assert "sk-fake-0001" not in settings_file.read_text(encoding="utf-8")


def test_double_save_does_not_double_encrypt(settings_file: Path) -> None:
    """已经是密文就不能再加密一次（否则第二次读就解不开了）。"""
    gui._save_settings({"provider_keys": json.dumps({"deepseek": "sk-fake-0001"})})
    first = _read_settings(settings_file)["provider_keys"]
    gui._save_settings({"target": "http://127.0.0.1:5000"})
    second = _read_settings(settings_file)["provider_keys"]
    assert _decoded_keys(second) == {"deepseek": "sk-fake-0001"}
    from hexhound import secretstore

    if secretstore.protection_available()[0]:
        assert second.count(secretstore.PREFIX) == 1, "不得出现嵌套加密"
        assert first == second, "未改动密钥时不应重新加密"


def test_undecryptable_keys_report_a_reason(app, client, token, monkeypatch) -> None:
    """换机器/换用户导致解不开时：必须给出原因，**不能**静默当成"没配过"。"""
    from hexhound import secretstore

    gui._save_settings({"provider_keys": json.dumps({"deepseek": "sk-fake-0001"})})
    monkeypatch.setattr(
        secretstore, "unprotect", lambda value: ("", "模拟：密文与当前用户不匹配")
    )
    assert gui._provider_keys() == {}
    assert "模拟" in gui._KEYSTORE_NOTE
    payload = client.get("/api/providers", headers=_auth(token)).get_json()
    assert "模拟" in payload["keystore_error"]
    assert payload["keys_saved"] == {}


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
def app(monkeypatch, settings_file: Path, tmp_path):
    """一份隔离的 GUI 应用（临时设置文件、临时运行产物目录、干净状态）。

    运行产物目录也要隔离：首页会列出历史运行，若不隔离就会去读用户真实的
    `~/.hexhound/runs/`（只读，但测试应当完全不碰用户数据）。
    """
    monkeypatch.setattr(gui, "STATE", gui.RunState())
    monkeypatch.setattr(gui.history, "data_home", lambda home=None: tmp_path / "hh-home")
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


# --------------------------------------------- P1 预算护栏 / 参数校验（桌面端）


def test_bad_budget_value_blocks_the_run_with_label_and_unit(app, client, token) -> None:
    """护栏填错必须在启动前拦住，并说清是哪个字段、单位是什么。"""
    response = client.post(
        "/api/run",
        json={"target": "http://127.0.0.1:5000", "max_cost": "-1", "max_tokens": "abc"},
        headers=_auth(token),
    )
    assert response.status_code == 400
    error = response.get_json()["error"]
    assert "费用上限" in error and "元" in error
    assert "Token 上限" in error
    assert gui.STATE.snapshot()["running"] is False


def test_all_five_budget_limits_reach_the_budget_object(app) -> None:
    """桌面端必须和 CLI 一样支持全部五个预算维度（曾经只生效两个）。"""
    from hexhound import runparams

    limits = runparams.limits_from_settings(
        {
            "max_cost": "3",
            "max_tokens": "200000",
            "max_llm_calls": "50",
            "max_tool_calls": "80",
            "max_seconds": "900",
        }
    )
    assert (limits.max_cost, limits.max_tokens, limits.max_llm_calls) == (3.0, 200000, 50)
    assert (limits.max_tool_calls, limits.max_seconds) == (80, 900.0)


def test_limit_fields_are_rendered_from_the_shared_spec(app, client, token) -> None:
    """界面上的参数输入框由字段定义渲染（标签/单位不会再和 CLI 漂移）。"""
    html = client.get("/").get_data(as_text=True)
    for key in ("max_cost", "max_tokens", "max_llm_calls", "max_tool_calls", "max_seconds"):
        assert f'name="{key}"' in html, key
    assert "费用上限" in html and "Token 上限" in html
    assert "不限制" in html


def test_new_settings_fields_survive_a_save(tmp_path, monkeypatch) -> None:
    """新增的预算字段同样遵循"未提交就不动"的保存语义。"""
    path = tmp_path / "settings.json"
    monkeypatch.setattr(gui, "SETTINGS_PATH", path)
    gui._save_settings({"max_tokens": "1000", "max_seconds": "300"})
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["max_tokens"] == "1000"
    assert stored["max_seconds"] == "300"
    gui._save_settings({"target": "http://127.0.0.1:5000"})
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["max_tokens"] == "1000"


# ------------------------------------------------------ P1 历史运行（只读产物）


def test_history_endpoint_lists_runs_from_disk(app, client, token, tmp_path, monkeypatch) -> None:
    home = tmp_path / "hh-home"  # 与 `app` fixture 里隔离的产物目录一致
    run_dir = home / "runs" / "127.0.0.1-20260101-000000"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {"target": "http://127.0.0.1:5000", "mode": "blackbox",
             "usage": {"total_tokens": 10, "estimated_cost": 0.01},
             "stats": {"findings": 1, "endpoints": 2}},
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (run_dir / "report.md").write_text("## 历史报告\n\n证据。\n", encoding="utf-8")
    (run_dir / "snapshot.json").write_text("{}", encoding="utf-8")

    payload = client.get("/api/history").get_json()
    assert [run["id"] for run in payload["runs"]] == ["127.0.0.1-20260101-000000"]
    assert payload["runs"][0]["findings"] == 1
    assert payload["status_labels"]

    detail = client.get("/api/history/127.0.0.1-20260101-000000").get_json()
    assert detail["markdown_source"] == "report"
    assert "历史报告" in detail["markdown"]
    # 首页要带上历史面板（清单由前端拉 /api/history 渲染，见浏览器冒烟测试）
    html = client.get("/").get_data(as_text=True)
    assert 'id="historyList"' in html and "历史运行" in html


def test_history_detail_of_unknown_run_is_404(app, client, token) -> None:
    assert client.get("/api/history/does-not-exist").status_code == 404


# ------------------------------------------------- P1 报表工作区（筛选/详情/导出/对比）


def _seed_run(home: Path, name: str = "127.0.0.1-20260101-000000", findings=None) -> Path:
    """造一次历史运行的产物（含 snapshot 里的 findings）。"""
    run_dir = home / "runs" / name
    run_dir.mkdir(parents=True, exist_ok=True)
    items = findings if findings is not None else [
        {"id": "HH-001", "title": "SQL 注入", "severity": "high", "status": "verified",
         "vuln_type": "sql_injection", "url": "http://127.0.0.1:5000/api/user?id=1",
         "evidence": "布尔差异", "param": "id"},
        {"id": "HH-002", "title": "反射型 XSS", "severity": "medium", "status": "candidate",
         "url": "http://127.0.0.1:5000/search", "evidence": "payload 回显"},
    ]
    (run_dir / "run.json").write_text(
        json.dumps({"target": "http://127.0.0.1:5000", "mode": "blackbox",
                    "usage": {"total_tokens": 10, "estimated_cost": 0.01},
                    "stats": {"findings": len(items), "endpoints": 2}}, ensure_ascii=False),
        encoding="utf-8",
    )
    (run_dir / "report.md").write_text("## 历史报告\n\n正文\n", encoding="utf-8")
    (run_dir / "snapshot.json").write_text(
        json.dumps({"schema_version": 2, "target": "http://127.0.0.1:5000", "goal": "g",
                    "result": {"findings": items}}, ensure_ascii=False),
        encoding="utf-8",
    )
    return run_dir


def test_findings_endpoint_returns_current_state(app, client, token) -> None:
    gui.STATE.findings = [{"id": "HH-009", "title": "当前发现", "status": "verified"}]
    payload = client.get("/api/findings").get_json()
    assert payload["run"] == "current"
    assert payload["source"] == "current"
    assert [item["id"] for item in payload["findings"]] == ["HH-009"]


def test_findings_endpoint_reads_a_history_run(app, client, token, tmp_path) -> None:
    _seed_run(tmp_path / "hh-home")
    payload = client.get("/api/findings?run=127.0.0.1-20260101-000000").get_json()
    assert payload["source"] == "snapshot"
    assert {item["id"] for item in payload["findings"]} == {"HH-001", "HH-002"}
    assert payload["findings"][0]["param"] == "id", "详情面板要用的字段必须带出来"


def test_findings_endpoint_unknown_run_is_404(app, client, token) -> None:
    assert client.get("/api/findings?run=nope").status_code == 404


def test_export_json_download(app, client, token, tmp_path) -> None:
    _seed_run(tmp_path / "hh-home")
    response = client.get("/api/export?format=json&run=127.0.0.1-20260101-000000")
    assert response.status_code == 200
    assert "attachment" in response.headers["Content-Disposition"]
    payload = json.loads(response.get_data(as_text=True))
    assert len(payload["findings"]) == 2
    assert payload["source"] == "snapshot"


def test_export_markdown_separates_candidates_from_verified(app, client, token, tmp_path) -> None:
    """导出文案必须把候选项与已复核分开，并写明候选项不是确认漏洞。"""
    _seed_run(tmp_path / "hh-home")
    response = client.get("/api/export?format=markdown&run=127.0.0.1-20260101-000000")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "已复核：1 条" in body
    assert "待复核候选：1 条" in body
    assert "候选项**不是**已确认漏洞" in body


def test_export_rejects_unknown_format(app, client, token) -> None:
    assert client.get("/api/export?format=xml").status_code == 400


def test_compare_reports_new_persisting_fixed_and_unknown(app, client, token, tmp_path) -> None:
    """跨运行对比：新增 / 仍存在 / 疑似已修复 / 无法判定 四类都要分得清。"""
    _seed_run(
        tmp_path / "hh-home",
        findings=[
            {"id": "HH-001", "title": "SQL 注入", "severity": "high", "status": "verified",
             "url": "http://127.0.0.1:5000/api/user?id=1"},
            {"id": "HH-002", "title": "已修的问题", "severity": "low", "status": "verified",
             "url": "http://127.0.0.1:5000/fixed"},
            {"id": "HH-003", "title": "没测到的位置", "severity": "medium", "status": "verified",
             "url": "http://127.0.0.1:5000/untouched"},
        ],
    )
    # 本次：HH-001 仍在（同一指纹），另有一条新的；/fixed 本次被覆盖且无问题 → 疑似已修复
    gui.STATE.findings = [
        {"id": "HH-101", "title": "SQL 注入", "severity": "high", "status": "verified",
         "url": "http://127.0.0.1:5000/api/user?id=1"},
        {"id": "HH-102", "title": "新发现", "severity": "critical", "status": "verified",
         "url": "http://127.0.0.1:5000/new"},
    ]
    payload = client.get("/api/compare?with=127.0.0.1-20260101-000000").get_json()
    assert payload["against"] == "127.0.0.1-20260101-000000"
    assert payload["current_count"] == 2 and payload["previous_count"] == 3
    assert payload["counts"]["persisting"] >= 1
    assert payload["counts"]["new"] >= 1
    # "没测到的位置" 绝不能算成已修复
    unknown_titles = {item["title"] for item in payload["unknown"]}
    assert "没测到的位置" in unknown_titles


def test_compare_requires_with(app, client, token) -> None:
    assert client.get("/api/compare").status_code == 400
    assert client.get("/api/compare?with=nope").status_code == 404


def test_workspace_controls_are_rendered(app, client, token) -> None:
    """筛选/详情/导出/对比四组控件都要在页面上（否则功能等于没做）。"""
    html = client.get("/").get_data(as_text=True)
    for marker in ('id="filterStatus"', 'id="filterSeverity"', 'id="filterText"',
                   'id="detailPane"', 'id="exportJson"', 'id="exportMarkdown"',
                   'id="compareSelect"', 'id="compareBtn"'):
        assert marker in html, marker

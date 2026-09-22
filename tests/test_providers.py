"""模型提供商预设、按角色模型解析与设置面板接口的测试（纯本地，不打真实 API）。"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.config import (  # noqa: E402
    Config,
    normalize_base_url,
    provider_from_base_url,
    resolve_provider,
)
from hexhound.llm import classify_error  # noqa: E402
from hexhound.providers import (  # noqa: E402
    ROLE_ENV_SUFFIX,
    describe_presets,
    env_key_name,
    get_preset,
    guess_preset,
    mask_key,
    pricing_for,
    pricing_known,
    provider_keys,
)

ENV_KEYS = (
    "LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY", "ALLOWED_HOSTS",
    "PROVIDER_DEEPSEEK_API_KEY", "PROVIDER_OPENAI_API_KEY",
) + tuple(f"LLM_{suffix}_MODEL" for suffix in ROLE_ENV_SUFFIX.values()) + tuple(
    f"LLM_{suffix}_PROVIDER" for suffix in ROLE_ENV_SUFFIX.values()
)


class EnvIsolation(unittest.TestCase):
    """每个用例用干净的环境变量，避免互相污染（也不受开发机 .env 影响）。"""

    def setUp(self) -> None:
        self._saved = {key: os.environ.get(key) for key in ENV_KEYS}
        for key in ENV_KEYS:
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class PresetTests(unittest.TestCase):
    def test_all_presets_have_unique_keys(self) -> None:
        keys = provider_keys()
        self.assertEqual(len(keys), len(set(keys)))
        self.assertGreaterEqual(len(keys), 10)

    def test_describe_presets_shape(self) -> None:
        rows = describe_presets()
        by_key = {row["key"]: row for row in rows}
        self.assertIn("deepseek", by_key)
        deepseek = by_key["deepseek"]
        self.assertTrue(deepseek["base_url"].startswith("https://"))
        self.assertIn(deepseek["default_model"], deepseek["models"])
        self.assertTrue(deepseek["key_required"])
        self.assertEqual(deepseek["env_key"], "PROVIDER_DEEPSEEK_API_KEY")

    def test_local_providers_do_not_require_key(self) -> None:
        by_key = {row["key"]: row for row in describe_presets()}
        for key in ("ollama", "vllm", "custom"):
            self.assertFalse(by_key[key]["key_required"], key)

    def test_custom_and_vllm_have_no_default_model(self) -> None:
        # 这两个必须由用户自己填模型名，否则界面会给出一个不存在的默认值
        self.assertEqual(get_preset("custom").default_model, "")
        self.assertEqual(get_preset("vllm").default_model, "")

    def test_lookup_is_case_insensitive_and_alias_aware(self) -> None:
        self.assertIs(get_preset("DeepSeek"), get_preset("deepseek"))
        self.assertIsNotNone(get_preset("openai"))
        self.assertIsNone(get_preset("not-a-provider"))

    def test_env_key_name(self) -> None:
        self.assertEqual(env_key_name("deepseek"), "PROVIDER_DEEPSEEK_API_KEY")
        self.assertEqual(env_key_name("silicon-flow"), "PROVIDER_SILICON_FLOW_API_KEY")

    def test_guess_preset_from_url(self) -> None:
        self.assertEqual(guess_preset("https://api.deepseek.com").key, "deepseek")
        self.assertEqual(
            guess_preset("https://dashscope.aliyuncs.com/compatible-mode/v1").key, "qwen"
        )
        self.assertIsNone(guess_preset("https://my-gateway.internal/v1"))

    def test_mask_key_never_reveals_middle(self) -> None:
        masked = mask_key("sk-1234567890abcdefghij")
        self.assertIn("…", masked)
        self.assertNotIn("567890", masked)
        self.assertEqual(mask_key(""), "")
        self.assertEqual(mask_key("abc"), "ab…")

    def test_pricing_known_and_override(self) -> None:
        self.assertTrue(pricing_known("deepseek"))
        self.assertFalse(pricing_known("custom"))
        self.assertFalse(pricing_known("ollama"))
        base = pricing_for("deepseek")
        self.assertGreater(base["input_cache_miss_per_million"], 0)
        with patch.dict(os.environ, {"PRICE_INPUT": "9.9"}):
            self.assertEqual(pricing_for("deepseek")["input_cache_miss_per_million"], 9.9)
        # 自定义提供商也能靠环境变量获得计价（否则费用永远显示 0）
        with patch.dict(os.environ, {"PRICE_INPUT": "1.5", "PRICE_OUTPUT": "3"}):
            self.assertTrue(pricing_known("custom"))


class ConfigProviderTests(EnvIsolation):
    def test_no_provider_configured_raises_helpful_error(self) -> None:
        """默认不预设提供商：没配就报错并给出 4 种配置方式（而不是偷偷用某一家）。"""
        with self.assertRaises(ValueError) as ctx:
            Config.from_env()
        message = str(ctx.exception)
        self.assertIn("还没有选择模型提供商", message)
        for hint in ("hexhound setup", "hexhound providers", "LLM_PROVIDER", "--provider"):
            self.assertIn(hint, message)

    def test_provider_preset_fills_base_url_and_model(self) -> None:
        os.environ.update({"LLM_PROVIDER": "deepseek", "LLM_API_KEY": "sk-test"})
        config = Config.from_env()
        self.assertEqual(config.provider, "deepseek")
        self.assertEqual(config.base_url, "https://api.deepseek.com")
        self.assertEqual(config.model, "deepseek-v4-flash")

    def test_explicit_env_overrides_preset(self) -> None:
        os.environ.update(
            {
                "LLM_PROVIDER": "deepseek",
                "LLM_API_KEY": "sk-test",
                "LLM_MODEL": "deepseek-v4-pro",
                "LLM_BASE_URL": "https://my-proxy.example/v1",
            }
        )
        config = Config.from_env()
        self.assertEqual(config.model, "deepseek-v4-pro")
        self.assertEqual(config.base_url, "https://my-proxy.example/v1")

    def test_legacy_env_still_works(self) -> None:
        """v0.1 的 .env（只有 LLM_BASE_URL/LLM_MODEL）必须继续可用。"""
        os.environ.update(
            {
                "LLM_API_KEY": "sk-test",
                "LLM_BASE_URL": "https://api.moonshot.cn/v1",
                "LLM_MODEL": "moonshot-v1-8k",
            }
        )
        config = Config.from_env()
        self.assertEqual(config.provider, "moonshot")  # 由 URL 反查得到
        self.assertEqual(config.model, "moonshot-v1-8k")

    def test_unknown_base_url_becomes_custom(self) -> None:
        os.environ.update(
            {
                "LLM_API_KEY": "sk-test",
                "LLM_BASE_URL": "https://gateway.corp/v1",
                "LLM_MODEL": "corp-model",
            }
        )
        config = Config.from_env()
        self.assertEqual(config.provider, "custom")
        self.assertEqual(config.base_url, "https://gateway.corp/v1")
        self.assertEqual(config.model, "corp-model")

    def test_custom_without_model_raises(self) -> None:
        os.environ.update(
            {"LLM_API_KEY": "sk-test", "LLM_BASE_URL": "https://gateway.corp/v1"}
        )
        with self.assertRaises(ValueError) as ctx:
            Config.from_env()
        self.assertIn("没有指定模型", str(ctx.exception))

    def test_provider_selection_uses_preset_defaults(self) -> None:
        os.environ.update({"LLM_PROVIDER": "qwen", "PROVIDER_QWEN_API_KEY": "sk-qwen"})
        config = Config.from_env()
        self.assertEqual(config.provider, "qwen")
        self.assertEqual(config.base_url, "https://dashscope.aliyuncs.com/compatible-mode/v1")
        self.assertEqual(config.model, "qwen-plus")
        self.assertEqual(config.api_key, "sk-qwen")

    def test_dedicated_key_wins_over_shared(self) -> None:
        os.environ.update(
            {"LLM_PROVIDER": "deepseek", "LLM_API_KEY": "sk-shared",
             "PROVIDER_DEEPSEEK_API_KEY": "sk-dedicated"}
        )
        config = Config.from_env()
        self.assertEqual(config.api_key, "sk-dedicated")
        self.assertEqual(config.api_key_source, "PROVIDER_DEEPSEEK_API_KEY")

    def test_missing_key_raises_with_actionable_message(self) -> None:
        os.environ["LLM_PROVIDER"] = "openai"
        with self.assertRaises(ValueError) as ctx:
            Config.from_env()
        message = str(ctx.exception)
        self.assertIn("PROVIDER_OPENAI_API_KEY", message)
        self.assertIn("模型提供商", message)

    def test_local_provider_allows_empty_key(self) -> None:
        os.environ["LLM_PROVIDER"] = "ollama"
        config = Config.from_env()
        self.assertEqual(config.provider, "ollama")
        self.assertEqual(config.api_key, "")
        self.assertEqual(config.base_url, "http://127.0.0.1:11434/v1")

    def test_custom_provider_without_base_url_raises(self) -> None:
        os.environ.update({"LLM_PROVIDER": "custom", "LLM_API_KEY": "sk-x"})
        os.environ.pop("LLM_BASE_URL", None)  # 自定义提供商必须自己给 URL
        with self.assertRaises(ValueError) as ctx:
            Config.from_env()
        self.assertIn("base_url", str(ctx.exception))

    def test_role_model_resolution(self) -> None:
        os.environ.update(
            {
                "LLM_PROVIDER": "deepseek",
                "PROVIDER_DEEPSEEK_API_KEY": "sk-deepseek",
                "LLM_VERIFY_MODEL": "deepseek-v4-pro",
            }
        )
        config = Config.from_env()
        verify = config.role_model("verify")
        self.assertTrue(verify.overridden)
        self.assertEqual(verify.model, "deepseek-v4-pro")
        self.assertEqual(verify.provider, "deepseek")
        # 未覆盖的角色完全跟随默认
        recon = config.role_model("recon")
        self.assertFalse(recon.overridden)
        self.assertEqual(recon.model, config.model)

    def test_role_can_switch_provider_entirely(self) -> None:
        os.environ.update(
            {
                "LLM_PROVIDER": "deepseek",
                "PROVIDER_DEEPSEEK_API_KEY": "sk-deepseek",
                "PROVIDER_OPENAI_API_KEY": "sk-openai",
                "LLM_VERIFY_PROVIDER": "openai",
            }
        )
        config = Config.from_env()
        verify = config.role_model("verify")
        self.assertEqual(verify.provider, "openai")
        self.assertEqual(verify.api_key, "sk-openai")
        self.assertIn("openai.com", verify.base_url)

    def test_role_override_falls_back_to_shared_key(self) -> None:
        """角色换了提供商但没配该家 key 时，退回共享 key 并如实说明来源。"""
        os.environ.update(
            {"LLM_PROVIDER": "deepseek", "LLM_API_KEY": "sk-shared",
             "LLM_VERIFY_PROVIDER": "openai"}
        )
        verify = Config.from_env().role_model("verify")
        self.assertEqual(verify.provider, "openai")
        self.assertEqual(verify.api_key, "sk-shared")
        self.assertEqual(verify.api_key_source, "LLM_API_KEY")

    def test_role_models_resolved_covers_all_roles(self) -> None:
        os.environ.update({"LLM_PROVIDER": "deepseek", "LLM_API_KEY": "sk-test"})
        resolved = Config.from_env().role_models_resolved()
        self.assertEqual(set(resolved), set(ROLE_ENV_SUFFIX))

    def test_normalize_base_url(self) -> None:
        self.assertEqual(normalize_base_url("api.deepseek.com"), "https://api.deepseek.com")
        self.assertEqual(normalize_base_url("https://x/v1/"), "https://x/v1")
        self.assertEqual(normalize_base_url(""), "")

    def test_resolve_provider_does_not_guess(self) -> None:
        """没配置就返回空串——不猜默认值，避免静默按某家付费模型跑起来。"""
        self.assertEqual(resolve_provider(""), "")
        self.assertEqual(resolve_provider("deepseek"), "deepseek")
        self.assertEqual(resolve_provider("DEEPSEEK"), "deepseek")
        self.assertEqual(resolve_provider("some-gateway"), "custom")

    def test_provider_from_base_url(self) -> None:
        self.assertEqual(provider_from_base_url("https://api.deepseek.com"), "deepseek")
        self.assertEqual(provider_from_base_url("https://whatever/v1"), "custom")


class ErrorClassificationTests(unittest.TestCase):
    def test_auth_error(self) -> None:
        category, advice = classify_error(RuntimeError("401 Authentication Fails"))
        self.assertEqual(category, "auth")
        self.assertIn("key", advice)

    def test_model_list_error_surfaces_original_text(self) -> None:
        """提供商在 400 里列出合法模型名时，要把原文带出来（比泛泛提示有用）。"""
        exc = RuntimeError(
            "400 - {'error': {'message': 'The supported API model names are deepseek-flash, deepseek-v4-pro'}}"
        )
        category, advice = classify_error(exc)
        self.assertEqual(category, "model")
        self.assertIn("deepseek-v4-pro", advice)

    def test_quota_and_network(self) -> None:
        self.assertEqual(classify_error(RuntimeError("429 rate limit"))[0], "quota")
        self.assertEqual(classify_error(RuntimeError("APITimeoutError: timed out"))[0], "network")


class GuiProviderPanelTests(EnvIsolation):
    """设置面板的后端接口（用 Flask test_client，不发真实请求）。

    注意：面板接口现在要求本机会话令牌（`gui.TOKEN_HEADER`）——那是防 CSRF 的
    真实契约，所以这里**如实带上令牌**，而不是把校验关掉。
    """

    @classmethod
    def setUpClass(cls) -> None:
        from hexhound import gui as gui_module

        cls.gui = gui_module
        cls.app = gui_module.create_app()
        cls.client = cls.app.test_client()
        cls.token = cls.app.config["HEXHOUND_LOCAL_TOKEN"]

    def post(self, *args, **kwargs):
        """带会话令牌的 POST（模拟界面自己的请求）。"""
        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault(self.gui.TOKEN_HEADER, self.token)
        return self.client.post(*args, headers=headers, **kwargs)

    def test_index_renders_provider_panel(self) -> None:
        html = self.client.get("/").get_data(as_text=True)
        for token in ("providerSelect", "modelOptions", "testBtn", "envBtn", "roleModelBox"):
            self.assertIn(token, html, token)

    def test_providers_endpoint_defaults_to_empty(self) -> None:
        """没配置时 active 为空（界面会显示"请选择提供商"，不预选付费服务）。"""
        with patch.object(self.gui, "_load_settings", lambda: {}), patch.dict(
            os.environ, {"LLM_PROVIDER": "", "LLM_BASE_URL": ""}, clear=False
        ):
            payload = self.client.get("/api/providers").get_json()
        self.assertEqual(payload["active"], "")
        self.assertGreaterEqual(len(payload["presets"]), 10)

    def test_providers_endpoint_reflects_settings(self) -> None:
        with patch.object(self.gui, "_load_settings", lambda: {"provider": "qwen"}):
            payload = self.client.get("/api/providers").get_json()
        self.assertEqual(payload["active"], "qwen")
        self.assertIn("pricing", payload)

    def test_provider_key_is_saved_and_masked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / "settings.json"
            saved: dict = {}

            def fake_save(data: dict) -> None:
                saved.update(data)
                settings.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

            with (
                patch.object(self.gui, "_load_settings", lambda: dict(saved)),
                patch.object(self.gui, "_save_settings", fake_save),
            ):
                resp = self.post(
                    "/api/provider_key",
                    json={"provider": "moonshot", "api_key": "sk-moonshot-abcdef123456"},
                )
                self.assertEqual(resp.status_code, 200)
                payload = resp.get_json()
                self.assertEqual(payload["provider"], "moonshot")
                self.assertNotIn("abcdef123456", payload["masked"])
            keys = json.loads(saved["provider_keys"])
            self.assertEqual(keys["moonshot"], "sk-moonshot-abcdef123456")

    def test_provider_key_rejects_empty(self) -> None:
        resp = self.post("/api/provider_key", json={"provider": "openai", "api_key": "  "})
        self.assertEqual(resp.status_code, 400)

    def test_provider_test_requires_model(self) -> None:
        resp = self.post("/api/provider_test", json={"provider": "custom", "model": ""})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("模型名", resp.get_json()["error"])

    def test_provider_test_requires_url_for_custom(self) -> None:
        resp = self.post(
            "/api/provider_test", json={"provider": "custom", "model": "local-model"}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("base_url", resp.get_json()["error"])

    def test_provider_test_requires_key_for_hosted(self) -> None:
        with patch.object(self.gui, "_provider_keys", lambda: {}), patch.dict(
            os.environ, {"LLM_API_KEY": ""}, clear=False
        ):
            os.environ.pop("LLM_API_KEY", None)
            resp = self.post(
                "/api/provider_test", json={"provider": "openai", "model": "gpt-4o-mini"}
            )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("密钥", resp.get_json()["error"])

    def test_provider_test_reports_failure_without_network(self) -> None:
        """打桩掉真实客户端：失败路径也要给出可读结论而不是 500。"""
        class FakeClient:
            def __init__(self, *a, **k) -> None:
                pass

            def test_connection(self, timeout: float = 30.0):
                from hexhound.llm import ConnectionCheck

                return ConnectionCheck(
                    ok=False, provider="openai", model="gpt-4o-mini",
                    message="API key 无效或未授权", category="auth",
                )

        with patch.object(self.gui, "LLMClient", FakeClient):
            resp = self.post(
                "/api/provider_test",
                json={"provider": "openai", "model": "gpt-4o-mini", "api_key": "sk-x"},
            )
        payload = resp.get_json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["category"], "auth")

    def test_provider_test_rejects_empty_provider(self) -> None:
        """没选提供商时，"自定义"需要一个 base_url；空提供商应给出明确提示。"""
        resp = self.post("/api/provider_test", json={"provider": "", "model": "m"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("base_url", resp.get_json()["error"])

    def _post_write_env(self, tmp: str, payload: dict):
        """write_env 写到 `Path.cwd()/.env`（打包后即 exe 同目录），测试里换掉 cwd。"""
        with patch("pathlib.Path.cwd", staticmethod(lambda: Path(tmp))):
            return self.post("/api/write_env", json=payload)

    def test_write_env_updates_keys_and_keeps_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text(
                "# 我自己写的注释\n"
                "ALLOWED_HOSTS=127.0.0.1\n"
                "VISION_API_KEY=sk-vision\n"
                "CUSTOM_THING=keep-me\n",
                encoding="utf-8",
            )
            resp = self._post_write_env(
                tmp,
                {
                    "provider": "qwen",
                    "model": "qwen-max",
                    "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
                    "api_key": "sk-qwen-key",
                    "role_model_verify": "qwen-max",
                },
            )
            self.assertEqual(resp.status_code, 200)
            text = env_file.read_text(encoding="utf-8")
            self.assertIn("# 我自己写的注释", text)      # 注释保留
            self.assertIn("CUSTOM_THING=keep-me", text)  # 未知键保留
            self.assertIn("ALLOWED_HOSTS=127.0.0.1", text)
            self.assertIn("LLM_PROVIDER=qwen", text)
            self.assertIn("LLM_MODEL=qwen-max", text)
            self.assertIn("PROVIDER_QWEN_API_KEY=sk-qwen-key", text)
            self.assertIn("LLM_VERIFY_MODEL=qwen-max", text)
            self.assertTrue((Path(tmp) / ".env.bak").exists())  # 写入前备份

    def test_write_env_replaces_existing_key_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("LLM_MODEL=old-model\nMAX_STEPS=30\n", encoding="utf-8")
            self._post_write_env(
                tmp,
                {"provider": "deepseek", "model": "new-model",
                 "base_url": "https://api.deepseek.com", "api_key": "sk-x"},
            )
            lines = env_file.read_text(encoding="utf-8").splitlines()
            self.assertIn("LLM_MODEL=new-model", lines)
            self.assertIn("MAX_STEPS=30", lines)
            self.assertEqual(sum(1 for line in lines if line.startswith("LLM_MODEL=")), 1)


if __name__ == "__main__":
    unittest.main()

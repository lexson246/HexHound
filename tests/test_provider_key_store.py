"""供应商密钥存取：新密钥不得覆盖旧密钥，明文不得落盘/回填。

外部评审复现的两个真实缺陷（本文件逐条钉住）：

1. **保存 Qwen 之后 DeepSeek 的密钥消失**——`/api/provider_key` 直接
   `json.loads(settings["provider_keys"])`，而该字段落盘时是 **DPAPI 密文**：
   解析失败 → 退化成空字典 → 只写进新 provider 的那把 → 其它密钥全被清掉。
2. **遗留 `api_key` 仍会明文保存并被回填到页面**（`<input value="sk-…">`）。

这里的判据是"**磁盘上真的存了什么** + 页面真的收到了什么"，不看实现细节。
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import gui, secretstore  # noqa: E402

FAKE_DEEPSEEK = "sk-fake-deepseek-0001"
FAKE_QWEN = "sk-fake-qwen-0002"


class ProviderKeyStoreTests(unittest.TestCase):
    """磁盘层的存取语义（不经过 HTTP，先把存储本身钉死）。"""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.settings = Path(self._tmp.name) / "settings.json"
        self._patcher = patch.object(gui, "SETTINGS_PATH", self.settings)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def read_keys(self) -> dict[str, str]:
        return gui._provider_keys()

    def read_file(self) -> dict:
        return json.loads(self.settings.read_text(encoding="utf-8"))

    def test_second_provider_does_not_wipe_the_first(self) -> None:
        ok, why = gui._store_provider_key("deepseek", FAKE_DEEPSEEK)
        self.assertTrue(ok, why)
        ok, why = gui._store_provider_key("qwen", FAKE_QWEN)
        self.assertTrue(ok, why)
        keys = self.read_keys()
        self.assertEqual(keys.get("deepseek"), FAKE_DEEPSEEK, f"第一把密钥被覆盖了：{keys}")
        self.assertEqual(keys.get("qwen"), FAKE_QWEN)

    def test_keys_are_encrypted_on_disk_when_supported(self) -> None:
        gui._store_provider_key("deepseek", FAKE_DEEPSEEK)
        raw = str(self.read_file().get("provider_keys") or "")
        if secretstore.is_protected(raw):
            self.assertNotIn(FAKE_DEEPSEEK, self.settings.read_text(encoding="utf-8"))
        else:  # 非 Windows / 无 DPAPI：至少不能比明文 JSON 更糟
            self.assertIn("deepseek", raw)

    def test_unreadable_keystore_refuses_instead_of_wiping(self) -> None:
        """解密失败时**拒绝保存**：不能把读不出来的旧密钥覆盖掉。"""
        self.settings.write_text(
            json.dumps({"provider_keys": secretstore.PREFIX + "not-a-real-blob"}), encoding="utf-8"
        )
        ok, why = gui._store_provider_key("qwen", FAKE_QWEN)
        self.assertFalse(ok, "读不出旧密钥时必须拒绝保存")
        self.assertIn("未保存", why)
        self.assertIn("not-a-real-blob", self.settings.read_text(encoding="utf-8"))

    def test_legacy_plaintext_api_key_is_migrated_and_cleared(self) -> None:
        """旧文件里的明文 `api_key` → 迁进 provider_keys，明文键清空、不再落盘。"""
        self.settings.write_text(
            json.dumps(
                {"provider": "deepseek", "api_key": FAKE_DEEPSEEK, "provider_keys": "{}"},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        gui._save_settings({"model": "deepseek-flash"})  # 任意一次保存都会触发迁移
        data = self.read_file()
        self.assertEqual(str(data.get("api_key") or ""), "", "明文 api_key 必须被清空")
        self.assertEqual(self.read_keys().get("deepseek"), FAKE_DEEPSEEK)
        self.assertNotIn(FAKE_DEEPSEEK, json.dumps(data, ensure_ascii=False))

    def test_migration_keeps_other_providers(self) -> None:
        gui._store_provider_key("qwen", FAKE_QWEN)
        self.settings.write_text(
            json.dumps(
                {
                    "provider": "deepseek",
                    "api_key": FAKE_DEEPSEEK,
                    "provider_keys": self.read_file().get("provider_keys", "{}"),
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        gui._save_settings({"model": "deepseek-flash"})
        keys = self.read_keys()
        self.assertEqual(keys.get("qwen"), FAKE_QWEN, f"迁移不能丢别的提供商：{keys}")
        self.assertEqual(keys.get("deepseek"), FAKE_DEEPSEEK)


class ProviderKeyApiTests(unittest.TestCase):
    """HTTP 层：页面不再拿到明文密钥，保存接口不覆盖旧密钥。"""

    def setUp(self) -> None:
        try:
            import flask  # noqa: F401
        except ImportError:
            self.skipTest("需要真实 Flask")
        if getattr(sys.modules.get("flask"), "__hexhound_flask_stub__", False):
            self.skipTest("需要真实 Flask（当前是替身）")
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.settings = Path(self._tmp.name) / "settings.json"
        for target, value in (
            (gui, "SETTINGS_PATH"),
            (gui, "STATE"),
        ):
            patcher = patch.object(target, value, gui.RunState() if value == "STATE" else self.settings)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.app = gui.create_app()
        self.client = self.app.test_client()
        self.headers = {gui.TOKEN_HEADER: self.app.config["HEXHOUND_LOCAL_TOKEN"]}

    def test_index_never_renders_the_plaintext_key(self) -> None:
        gui._store_provider_key("deepseek", FAKE_DEEPSEEK)
        with patch.object(gui, "_load_settings", wraps=gui._load_settings):
            body = self.client.get("/", headers=self.headers).get_data(as_text=True)
        self.assertNotIn(FAKE_DEEPSEEK, body, "页面里不能出现明文密钥")
        self.assertIn('value=""', body)

    def test_saving_a_second_provider_keeps_the_first_over_http(self) -> None:
        first = self.client.post(
            "/api/provider_key", json={"provider": "deepseek", "api_key": FAKE_DEEPSEEK},
            headers=self.headers,
        )
        self.assertEqual(first.status_code, 200, first.get_data(as_text=True))
        second = self.client.post(
            "/api/provider_key", json={"provider": "qwen", "api_key": FAKE_QWEN},
            headers=self.headers,
        )
        self.assertEqual(second.status_code, 200, second.get_data(as_text=True))
        keys = gui._provider_keys()
        self.assertEqual(keys.get("deepseek"), FAKE_DEEPSEEK)
        self.assertEqual(keys.get("qwen"), FAKE_QWEN)

    def test_save_endpoint_does_not_store_plaintext_api_key(self) -> None:
        response = self.client.post(
            "/api/save",
            json={**gui.DEFAULTS, "provider": "deepseek", "api_key": FAKE_DEEPSEEK},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        text = self.settings.read_text(encoding="utf-8")
        self.assertNotIn(FAKE_DEEPSEEK, text)
        self.assertEqual(gui._provider_keys().get("deepseek"), FAKE_DEEPSEEK)

    def test_empty_key_field_keeps_the_saved_key(self) -> None:
        gui._store_provider_key("deepseek", FAKE_DEEPSEEK)
        response = self.client.post(
            "/api/save",
            json={**gui.DEFAULTS, "provider": "deepseek", "api_key": ""},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(gui._provider_keys().get("deepseek"), FAKE_DEEPSEEK)


if __name__ == "__main__":
    unittest.main()

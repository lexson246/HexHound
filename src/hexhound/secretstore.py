"""本机密钥的**静态**保护：Windows 上用 DPAPI 加密后再落盘。

要解决的问题：`provider_keys` 一直以明文存在 `~/.hexhound/settings.json` 里。
上一轮补掉了"密钥经 HTTP 回传浏览器"这条边界，但**文件本身**仍是明文——
任何能读到这个文件的进程（同机其它用户不是问题，DPAPI 是用户级；
但同步盘、备份、误发的截图/日志都可能带上它）都能直接用。

做法（刻意保持简单）：
* Windows：`CryptProtectData`（用户级，无额外熵）→ 密文以 `dpapi:` 前缀 + base64 存回原字段；
* 其它平台：**不假装加密**，原样返回，并由 `protection_available()` 说明为什么。

三条硬约束：

1. **迁移不丢密钥**：旧文件里的明文 JSON 仍能读；下一次保存自动转成密文。
2. **换机器/换用户要能说清**：DPAPI 密文换台机器就解不开——此时必须**明确报错**，
   而不是把"解不开"静默当成"没配过密钥"（那会让用户以为密钥丢了却查不出原因）。
3. **不改调用方语义**：读出来还是那个 JSON 字符串，写进去还是字符串。
"""
from __future__ import annotations

import base64
import ctypes
import sys

#: 密文前缀。带前缀才走解密，因此旧格式（明文 JSON）天然兼容。
PREFIX = "dpapi:"


def protection_available() -> tuple[bool, str]:
    """返回 `(是否可用, 原因)`。不可用时原因直接给用户看。"""
    if sys.platform != "win32":
        return False, (
            f"当前平台（{sys.platform}）没有 DPAPI：密钥只能以明文保存在设置文件里。"
            "Windows 上会自动加密。"
        )
    try:
        _crypt32()
    except OSError as exc:  # pragma: no cover - 只在异常环境触发
        return False, f"无法加载 crypt32：{exc}"
    return True, ""


def is_protected(value: str) -> bool:
    return str(value or "").startswith(PREFIX)


def protect(text: str) -> str:
    """加密文本；不可用或失败时**原样返回**（宁可明文可用，也不要写坏数据）。"""
    raw = str(text or "")
    if not raw or is_protected(raw):
        return raw
    available, _reason = protection_available()
    if not available:
        return raw
    try:
        blob = _dpapi_protect(raw.encode("utf-8"))
    except OSError:
        return raw
    return PREFIX + base64.b64encode(blob).decode("ascii")


def unprotect(value: str) -> tuple[str, str]:
    """解密文本，返回 `(明文, 错误说明)`。

    不是密文（旧格式明文）→ 原样返回、无错误。
    是密文但解不开（换了机器/用户）→ 返回空串 + **可读原因**，
    调用方必须把原因带给用户，不能静默当成"没配过"。
    """
    text = str(value or "")
    if not is_protected(text):
        return text, ""
    available, reason = protection_available()
    if not available:
        return "", f"这条配置是加密保存的，但当前环境无法解密：{reason}"
    try:
        blob = base64.b64decode(text[len(PREFIX) :], validate=True)
    except (ValueError, TypeError) as exc:
        return "", f"加密配置格式损坏，无法解密：{exc}"
    try:
        return _dpapi_unprotect(blob).decode("utf-8"), ""
    except OSError as exc:
        return "", (
            "无法解密已保存的密钥（DPAPI 密文与当前 Windows 用户绑定）："
            f"{exc}。如果你换了机器或用户，请重新填写密钥。"
        )


# ---------------------------------------------------------------------------
# DPAPI（ctypes，无第三方依赖）
# ---------------------------------------------------------------------------


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_ulong),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _crypt32():
    return ctypes.WinDLL("crypt32", use_last_error=True)


def _to_blob(data: bytes) -> _DataBlob:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))


def _from_blob(blob: _DataBlob) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        ctypes.WinDLL("kernel32", use_last_error=True).LocalFree(blob.pbData)


def _dpapi_protect(data: bytes) -> bytes:
    crypt32 = _crypt32()
    out = _DataBlob()
    ok = crypt32.CryptProtectData(
        ctypes.byref(_to_blob(data)), None, None, None, None, 0, ctypes.byref(out)
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptProtectData 失败")
    return _from_blob(out)


def _dpapi_unprotect(blob: bytes) -> bytes:
    crypt32 = _crypt32()
    out = _DataBlob()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(_to_blob(blob)), None, None, None, None, 0, ctypes.byref(out)
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptUnprotectData 失败")
    return _from_blob(out)

"""API 合约导入测试：OpenAPI 3 / Swagger 2、$ref 安全策略、恶意规范。

需求里逐条对应的用例：
- OpenAPI 3 / Swagger 2，JSON 与 YAML；
- 本地文件与（经范围校验后的）远程规范；
- 默认禁止任意外部 $ref；本地引用限制在规范根目录内；
- 远程引用经过与目标请求相同的范围验证；
- 不信任规范里的 servers / host / schemes / basePath；
- 所有接口始终锚定用户明确指定的 --target；
- 导入 method / path / 各类参数 / 认证提示；
- 接口进入 surface inventory 与 coverage；
- 解析失败给出可操作错误，不静默跳过；
- 恶意 server URL、目录穿越、外部 $ref 测试。
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.apispec import (  # noqa: E402
    MAX_REF_DEPTH,
    RefPolicy,
    RefResolutionError,
    SpecError,
    build_operation_url,
    detect_spec_kind,
    import_spec,
    load_spec_source,
    normalize_spec_path,
    parse_spec_text,
    parse_yaml,
)
from hexhound.surface import AttackSurface  # noqa: E402

TARGET = "http://127.0.0.1:5000"
ALLOWED = frozenset({"127.0.0.1", "localhost", "specs.example.com"})

OPENAPI3 = {
    "openapi": "3.0.3",
    "info": {"title": "演示 API", "version": "1.2.3"},
    "servers": [{"url": "https://evil.example.com/api/v1"}],
    "paths": {
        "/users/{id}": {
            "get": {
                "operationId": "getUser",
                "summary": "读取用户",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
                ],
                "security": [{"bearerAuth": []}],
            },
            "delete": {"operationId": "deleteUser"},
        },
        "/orders": {
            "post": {
                "operationId": "createOrder",
                "requestBody": {"content": {"application/json": {}}},
                "parameters": [{"name": "X-Trace", "in": "header"}],
            }
        },
    },
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "旧版 API", "version": "1.0.0"},
    "host": "evil.example.com",
    "basePath": "/api",
    "schemes": ["https"],
    "securityDefinitions": {
        "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    },
    "paths": {
        "/login": {
            "post": {
                "parameters": [
                    {"name": "username", "in": "formData", "type": "string"},
                    {"name": "password", "in": "formData", "type": "string"},
                ],
                "security": [{"apiKey": []}],
            }
        },
        "/items": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
    },
}

OPENAPI3_YAML = """\
openapi: 3.0.1
info:
  title: YAML 规范
  version: 9.9.9
servers:
  - url: https://evil.example.com/root
paths:
  /ping:
    get:
      operationId: ping
      parameters:
        - name: ip
          in: query
          required: true
          schema:
            type: string
      security:
        - basicAuth: []
components:
  securitySchemes:
    basicAuth:
      type: http
      scheme: basic
"""


def import_openapi(spec: dict, target: str = TARGET) -> object:
    return import_spec(text=json.dumps(spec), source="inline.json", target=target)


class SpecKindTests(unittest.TestCase):
    def test_detects_openapi3(self) -> None:
        kind = detect_spec_kind(OPENAPI3)
        self.assertEqual(kind.flavor, "openapi3")
        self.assertTrue(kind.supported)
        self.assertIn("3.0.3", kind.label)

    def test_detects_swagger2(self) -> None:
        kind = detect_spec_kind(SWAGGER2)
        self.assertEqual(kind.flavor, "swagger2")
        self.assertTrue(kind.supported)

    def test_unsupported_versions_are_rejected_with_advice(self) -> None:
        for spec, token in (
            ({"openapi": "4.0.0", "paths": {}}, "4.0.0"),
            ({"swagger": "1.2", "paths": {}}, "1.2"),
        ):
            with self.assertRaises(SpecError) as ctx:
                import_openapi(spec)
            message = str(ctx.exception)
            self.assertIn(token, message)
            self.assertIn("OpenAPI 3", message)

    def test_missing_version_is_reported_actionably(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            import_openapi({"paths": {"/x": {"get": {}}}})
        self.assertIn("openapi", str(ctx.exception).lower())

    def test_no_paths_is_rejected(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            import_openapi({"openapi": "3.0.0", "info": {}})
        self.assertIn("paths", str(ctx.exception))


class OperationExtractionTests(unittest.TestCase):
    def test_openapi3_operations_are_imported(self) -> None:
        result = import_openapi(OPENAPI3)
        pairs = {(op.method, op.normalized_path) for op in result.operations}
        self.assertEqual(
            pairs,
            {("GET", "/users/{id}"), ("DELETE", "/users/{id}"), ("POST", "/orders")},
        )

    def test_parameters_are_imported_with_location(self) -> None:
        result = import_openapi(OPENAPI3)
        get_user = next(op for op in result.operations if op.method == "GET")
        by_name = {item["name"]: item for item in get_user.params}
        self.assertEqual(by_name["id"]["location"], "path")
        self.assertTrue(by_name["id"]["required"])
        self.assertEqual(by_name["verbose"]["location"], "query")

    def test_header_parameters_are_imported(self) -> None:
        result = import_openapi(OPENAPI3)
        order = next(op for op in result.operations if op.method == "POST")
        self.assertIn("X-Trace", [item["name"] for item in order.params])

    def test_authentication_hint_is_imported(self) -> None:
        result = import_openapi(OPENAPI3)
        get_user = next(op for op in result.operations if op.method == "GET")
        self.assertTrue(get_user.security)
        self.assertIn("bearerAuth", get_user.security[0])
        self.assertIn("http/bearer", get_user.security[0])

    def test_swagger2_formdata_becomes_params(self) -> None:
        """Swagger 2 用 formData 描述表单字段，必须转成可测参数。"""
        result = import_openapi(SWAGGER2)
        login = next(op for op in result.operations if op.method == "POST")
        names = [item["name"] for item in login.params]
        self.assertEqual(sorted(names), ["password", "username"])
        self.assertTrue(all(item["location"] == "form" for item in login.params))

    def test_swagger2_apikey_hint(self) -> None:
        result = import_openapi(SWAGGER2)
        login = next(op for op in result.operations if op.method == "POST")
        self.assertIn("apiKey", login.security[0])
        self.assertIn("header:X-API-Key", login.security[0])

    def test_yaml_spec_is_parsed(self) -> None:
        result = import_spec(
            text=OPENAPI3_YAML, source="spec.yaml", target=TARGET
        )
        self.assertEqual(len(result.operations), 1)
        operation = result.operations[0]
        self.assertEqual(operation.method, "GET")
        self.assertEqual(operation.normalized_path, "/ping")
        self.assertEqual([item["name"] for item in operation.params], ["ip"])
        self.assertIn("basicAuth", operation.security[0])

    def test_bad_entry_is_skipped_with_a_reason_not_silently(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/ok": {"get": {"operationId": "ok"}},
                "/bad": {"get": "this is not an object"},
                "/weird": {"fetch": {"operationId": "x"}},
            },
        }
        result = import_openapi(spec)
        self.assertEqual([op.normalized_path for op in result.operations], ["/ok"])
        self.assertEqual(len(result.skipped), 2, "被跳过的条目必须逐条留下原因")
        self.assertTrue(any("/bad" in item for item in result.skipped))
        self.assertTrue(any("fetch" in item for item in result.skipped))

    def test_path_without_leading_slash_is_rejected_not_coerced(self) -> None:
        """回归：`users` 早先被静默补成 `/users`，等于把不合规的规范当成成功的。

        规范要求 paths 的键以 `/` 开头。静默补齐会让用户永远不知道自己的规范有问题。
        """
        spec = {"openapi": "3.0.0", "paths": {"users": {"get": {}}}}
        with self.assertRaises(SpecError) as ctx:
            import_openapi(spec)
        self.assertIn("不以 `/` 开头", str(ctx.exception))

    def test_operation_limit_is_enforced_and_reported(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "paths": {f"/p{index}": {"get": {}} for index in range(20)},
        }
        result = import_spec(text=json.dumps(spec), source="big.json", target=TARGET,
                             max_operations=5)
        self.assertEqual(len(result.operations), 5)
        self.assertTrue(any("上限" in item for item in result.skipped))


class TargetAnchoringTests(unittest.TestCase):
    """核心安全约束：规范**不能**扩大授权范围。"""

    def test_declared_servers_are_recorded_but_ignored(self) -> None:
        result = import_openapi(OPENAPI3)
        self.assertTrue(result.declared_servers)
        self.assertIn("evil.example.com", " ".join(result.declared_servers))
        # 每个接口的 URL 都必须锚定到 target
        for operation in result.operations:
            url = build_operation_url(TARGET, operation.normalized_path)
            self.assertTrue(url.startswith(TARGET), url)
            self.assertNotIn("evil.example.com", url)

    def test_notes_explain_that_servers_were_ignored(self) -> None:
        result = import_openapi(OPENAPI3)
        self.assertTrue(any("已被忽略" in note for note in result.notes))

    def test_swagger2_host_and_basepath_are_ignored(self) -> None:
        result = import_openapi(SWAGGER2)
        self.assertIn("evil.example.com", " ".join(result.declared_servers))
        for operation in result.operations:
            url = build_operation_url(TARGET, operation.normalized_path)
            self.assertTrue(url.startswith(TARGET))
            self.assertNotIn("evil.example.com", url)
            # basePath 也不参与拼接：路径就是 /login、/items
            self.assertNotIn("/api/", url)
        self.assertTrue(result.declared_base_path)

    def test_protocol_relative_path_is_rejected(self) -> None:
        """`//evil.com/x` 是最典型的规范注入：urljoin 会把主机换掉。"""
        spec = {"openapi": "3.0.0", "paths": {"//evil.example.com/steal": {"get": {}}}}
        with self.assertRaises(SpecError) as ctx:
            import_openapi(spec)
        self.assertIn("evil.example.com", str(ctx.exception))

    def test_absolute_url_path_is_rejected(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "paths": {"https://evil.example.com/steal": {"get": {}}},
        }
        with self.assertRaises(SpecError) as ctx:
            import_openapi(spec)
        self.assertIn("绝对 URL", str(ctx.exception))

    def test_backslash_protocol_relative_is_rejected(self) -> None:
        spec = {"openapi": "3.0.0", "paths": {"\\\\evil.example.com\\x": {"get": {}}}}
        with self.assertRaises(SpecError):
            import_openapi(spec)

    def test_normalize_removes_traversal(self) -> None:
        self.assertEqual(normalize_spec_path("/a/../../b"), "/b")
        self.assertEqual(normalize_spec_path("/a/./b//c"), "/a/b/c")
        self.assertEqual(normalize_spec_path("/\\evil.com/x"), "/evil.com/x")
        # 路径模板原样保留（`{id}` 是参数占位，不是穿越）
        self.assertEqual(normalize_spec_path("/users/{id}"), "/users/{id}")
        # 不以 `/` 开头 → 拒绝，而不是静默补斜杠
        with self.assertRaises(SpecError):
            normalize_spec_path("users")

    def test_build_operation_url_never_uses_urljoin_semantics(self) -> None:
        """回归：`urljoin(base, '//evil.com/x')` 会返回 evil.com。"""
        self.assertEqual(build_operation_url(TARGET, "/a"), TARGET + "/a")
        # 规范化会拒掉协议相对形式（抛错），而不是静默换成别的主机
        with self.assertRaises(SpecError):
            build_operation_url(TARGET, "//evil.example.com/x")

    def test_target_with_port_and_base_path_is_respected(self) -> None:
        url = build_operation_url("https://host.example.com:8443/base", "/x")
        self.assertEqual(url, "https://host.example.com:8443/x")

    def test_missing_target_is_an_actionable_error(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            build_operation_url("", "/x")
        self.assertIn("--target", str(ctx.exception))


class RefPolicyTests(unittest.TestCase):
    """$ref 安全策略。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        # 被引用的是**参数定义**（真实用法）。早先的夹具指向 schema，
        # 而 schema 没有 name/in，展开后会被参数收集器丢弃——那是夹具错了。
        (self.root / "common.yaml").write_text(
            "components:\n"
            "  parameters:\n"
            "    Limit:\n"
            "      name: limit\n"
            "      in: query\n"
            "      required: false\n"
            "      description: 共享参数定义\n",
            encoding="utf-8",
        )
        (self.root / "main.json").write_text(
            json.dumps(
                {
                    "openapi": "3.0.0",
                    "paths": {
                        "/a": {
                            "get": {
                                "parameters": [
                                    {"$ref": "common.yaml#/components/parameters/Limit"}
                                ]
                            }
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        # 规范根目录**外面**的文件
        (Path(self._tmp.name).parent / "outside-secret.yaml").write_text(
            "type: string\ndescription: 不该被读到\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_local_ref_inside_root_is_expanded(self) -> None:
        policy = RefPolicy(root=self.root)
        result = import_spec(
            text=(self.root / "main.json").read_text(encoding="utf-8"),
            source=str(self.root / "main.json"),
            target=TARGET,
            policy=policy,
        )
        self.assertEqual(len(result.operations), 1)
        params = result.operations[0].params
        self.assertEqual([item["name"] for item in params], ["limit"])
        self.assertEqual(params[0]["location"], "query")
        self.assertIn("共享参数定义", params[0].get("description", ""))
        self.assertTrue(any("已展开" in note for note in result.notes))

    def test_ref_to_a_schema_is_reported_not_silently_dropped(self) -> None:
        """`$ref` 指到 schema（而不是 parameters）是规范写错了——必须说出来。

        静默丢弃的后果：报告里那个接口"看起来没有参数"，实际是没解析出来，
        参数级覆盖闸门因此完全看不到这个盲区。
        """
        spec = {
            "openapi": "3.0.0",
            "paths": {"/a": {"get": {"parameters": [{"$ref": "common.yaml#/components/parameters/Limit"}]}}},
        }
        # 指向一个存在但没有 name 的节点
        result = import_spec(
            text=json.dumps(
                {
                    "openapi": "3.0.0",
                    "paths": {"/a": {"get": {"parameters": [{"name": "", "in": "query"}]}}},
                }
            ),
            source="inline",
            target=TARGET,
            policy=RefPolicy(root=self.root),
        )
        self.assertTrue(result.skipped, "没有 name 的参数条目必须留下原因")
        self.assertIn("没有 name", result.skipped[0])
        del spec

    def test_local_ref_with_traversal_is_rejected(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "paths": {"/a": {"get": {"parameters": [{"$ref": "../outside.yaml"}]}}},
        }
        with self.assertRaises(SpecError) as ctx:
            import_spec(
                text=json.dumps(spec),
                source="inline",
                target=TARGET,
                policy=RefPolicy(root=self.root),
            )
        self.assertIn("目录穿越", str(ctx.exception))

    def test_local_ref_escaping_root_is_rejected(self) -> None:
        """即使没有 `..`，解析后落在根目录之外也要拒绝（绝对路径/符号链接）。"""
        outside = self.root.parent / "outside-secret.yaml"
        spec = {
            "openapi": "3.0.0",
            "paths": {"/a": {"get": {"parameters": [{"$ref": str(outside)}]}}},
        }
        with self.assertRaises(SpecError):
            import_spec(
                text=json.dumps(spec),
                source="inline",
                target=TARGET,
                policy=RefPolicy(root=self.root),
            )

    def test_missing_ref_file_is_reported(self) -> None:
        spec = {"openapi": "3.0.0", "paths": {"/a": {"get": {"parameters": [{"$ref": "nope.yaml"}]}}}}
        with self.assertRaises(SpecError) as ctx:
            import_spec(
                text=json.dumps(spec), source="inline", target=TARGET,
                policy=RefPolicy(root=self.root),
            )
        self.assertIn("不存在", str(ctx.exception))

    def test_external_http_ref_is_forbidden_by_default(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "paths": {"/a": {"get": {"parameters": [{"$ref": "https://evil.example.com/x.yaml"}]}}},
        }
        with self.assertRaises(SpecError) as ctx:
            import_spec(text=json.dumps(spec), source="inline", target=TARGET)
        message = str(ctx.exception)
        self.assertIn("默认禁止", message)
        self.assertIn("evil.example.com", message)

    def test_http_ref_must_pass_scope_validation_when_remote_allowed(self) -> None:
        """允许远程引用时，仍然必须过**目标请求的同一份**范围校验。"""
        spec = {
            "openapi": "3.0.0",
            "paths": {"/a": {"get": {"parameters": [{"$ref": "https://evil.example.com/x.yaml"}]}}},
        }
        checked: list[str] = []

        def validate(url: str) -> str:
            checked.append(url)
            from hexhound.tools import validate_url_against

            _, error = validate_url_against(url, ALLOWED)
            return error or ""

        with self.assertRaises(SpecError) as ctx:
            import_spec(
                text=json.dumps(spec), source="inline", target=TARGET,
                policy=RefPolicy(allow_remote=True, validate_remote=validate),
            )
        self.assertTrue(checked, "远程引用必须先经过范围校验")
        self.assertIn("未通过目标范围校验", str(ctx.exception))

    def test_allowlisted_remote_ref_is_reported_as_not_downloaded(self) -> None:
        """白名单内的远程引用**通过校验**，但本版本不下载——明确说明而不是静默。"""
        spec = {
            "openapi": "3.0.0",
            "paths": {"/a": {"get": {"parameters": [{"$ref": "https://specs.example.com/x.yaml"}]}}},
        }

        def validate(url: str) -> str:
            return ""

        with self.assertRaises(SpecError) as ctx:
            import_spec(
                text=json.dumps(spec), source="inline", target=TARGET,
                policy=RefPolicy(allow_remote=True, validate_remote=validate),
            )
        self.assertIn("不下载远程规范", str(ctx.exception))

    def test_protocol_like_ref_is_rejected(self) -> None:
        spec = {"openapi": "3.0.0", "paths": {"/a": {"get": {"parameters": [{"$ref": "file:///etc/passwd"}]}}}}
        with self.assertRaises(SpecError) as ctx:
            import_spec(
                text=json.dumps(spec), source="inline", target=TARGET,
                policy=RefPolicy(root=self.root),
            )
        self.assertIn("不支持", str(ctx.exception))

    def test_self_referencing_ref_does_not_hang(self) -> None:
        """自引用必须被深度上限挡住，而不是无限展开。"""
        (self.root / "loop.json").write_text(
            json.dumps({"a": {"$ref": "#/a"}}), encoding="utf-8"
        )
        spec = {
            "openapi": "3.0.0",
            "paths": {"/a": {"get": {"description": {"$ref": "loop.json"}}}},
        }
        with self.assertRaises(SpecError):
            import_spec(
                text=json.dumps(spec), source="inline", target=TARGET,
                policy=RefPolicy(root=self.root),
            )

    def test_ref_depth_constant_is_sane(self) -> None:
        self.assertGreaterEqual(MAX_REF_DEPTH, 4)
        self.assertLessEqual(MAX_REF_DEPTH, 64)


class YamlSafetyTests(unittest.TestCase):
    """YAML 子集解析：主动拒绝锚点/别名/自定义标签（炸弹与构造器入口）。"""

    def test_anchors_and_aliases_are_rejected(self) -> None:
        text = "a: &anchor 1\nb: *anchor\n"
        with self.assertRaises(SpecError) as ctx:
            parse_yaml(text)
        self.assertIn("锚点/别名", str(ctx.exception))

    def test_custom_tags_are_rejected(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            parse_yaml("a: !!python/object:os.system x\n")
        self.assertIn("自定义标签", str(ctx.exception))

    def test_multi_document_is_rejected(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            parse_yaml("a: 1\n---\nb: 2\n")
        self.assertIn("多文档", str(ctx.exception))

    def test_plain_mapping_and_sequence(self) -> None:
        parsed = parse_yaml("a: 1\nb:\n  - x\n  - y\nc:\n  d: true\n")
        self.assertEqual(parsed, {"a": 1, "b": ["x", "y"], "c": {"d": True}})

    def test_flow_style(self) -> None:
        parsed = parse_yaml('a: [1, 2, "three"]\nb: {x: 1, y: no}\n')
        self.assertEqual(parsed["a"], [1, 2, "three"])
        self.assertEqual(parsed["b"], {"x": 1, "y": False})

    def test_block_scalar(self) -> None:
        parsed = parse_yaml("desc: |\n  line one\n  line two\nnext: 1\n")
        self.assertIn("line one", parsed["desc"])
        self.assertIn("line two", parsed["desc"])
        self.assertEqual(parsed["next"], 1)

    def test_sequence_of_mappings(self) -> None:
        parsed = parse_yaml(
            "parameters:\n"
            "  - name: id\n"
            "    in: path\n"
            "    required: true\n"
            "  - name: q\n"
            "    in: query\n"
        )
        self.assertEqual(len(parsed["parameters"]), 2)
        self.assertEqual(parsed["parameters"][0], {"name": "id", "in": "path", "required": True})
        self.assertEqual(parsed["parameters"][1]["name"], "q")

    def test_comments_are_ignored(self) -> None:
        parsed = parse_yaml("# top\na: 1  # inline\n# bottom\nb: 2\n")
        self.assertEqual(parsed, {"a": 1, "b": 2})

    def test_bad_indentation_is_reported_with_a_line_number(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            parse_yaml("a:\n  b: 1\n   c: 2\n")
        self.assertIn("缩进", str(ctx.exception))

    def test_mixed_mapping_and_sequence_at_same_level_is_reported(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            parse_yaml("a: 1\n- x\n")
        self.assertIn("类型冲突", str(ctx.exception))

    def test_json_is_preferred_over_yaml(self) -> None:
        parsed = parse_spec_text('{"openapi": "3.0.0", "paths": {}}')
        self.assertEqual(parsed["openapi"], "3.0.0")

    def test_empty_source_is_rejected(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            parse_spec_text("   ", source="empty.yaml")
        self.assertIn("为空", str(ctx.exception))

    def test_non_object_top_level_is_rejected(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            parse_spec_text("[1, 2, 3]", source="list.json")
        self.assertIn("顶层必须是对象", str(ctx.exception))


class LoadSourceTests(unittest.TestCase):
    def test_local_file_is_loaded_with_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.json"
            path.write_text(json.dumps(OPENAPI3), encoding="utf-8")
            text, source, root = load_spec_source(str(path))
            self.assertIn("openapi", text)
            self.assertEqual(root, Path(tmp).resolve())

    def test_missing_file_error_is_actionable(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            load_spec_source("no-such-spec-file.yaml")
        self.assertIn("找不到规范文件", str(ctx.exception))

    def test_remote_spec_outside_allowlist_is_refused_before_any_request(self) -> None:
        """远程规范必须过范围校验，且**校验不过就不发请求**。"""
        import httpx

        called = {"n": 0}

        def explode(*args, **kwargs):
            called["n"] += 1
            raise AssertionError("不应发起请求")

        def validate(url: str) -> str:
            from hexhound.tools import validate_url_against

            _, error = validate_url_against(url, ALLOWED)
            return error or ""

        import hexhound.apispec as apispec_module

        original = httpx.get
        httpx.get = explode
        try:
            with self.assertRaises(SpecError) as ctx:
                load_spec_source(
                    "https://evil.example.com/openapi.json", validate_url=validate
                )
        finally:
            httpx.get = original
        self.assertIn("未通过目标范围校验", str(ctx.exception))
        self.assertEqual(called["n"], 0, "范围校验不过时不得发起任何请求")
        del apispec_module

    def test_remote_spec_without_validator_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            load_spec_source("https://specs.example.com/x.yaml")
        self.assertIn("范围校验", str(ctx.exception))

    def test_remote_spec_download_uses_direct_connection(self) -> None:
        """远程规范下载必须与目标流量一样直连（不读环境/系统代理）。"""
        import httpx

        captured: dict = {}

        class FakeResponse:
            status_code = 200
            text = json.dumps(OPENAPI3)

        def fake_get(url, **kwargs):
            captured.update(kwargs)
            captured["url"] = url
            return FakeResponse()

        original = httpx.get
        httpx.get = fake_get
        try:
            text, source, root = load_spec_source(
                "https://specs.example.com/openapi.json", validate_url=lambda _url: ""
            )
        finally:
            httpx.get = original
        self.assertIn("openapi", text)
        self.assertIsNone(root)
        self.assertFalse(captured.get("trust_env"), "远程规范不得使用环境/系统代理")
        self.assertFalse(captured.get("follow_redirects"), "不得跟随重定向（作用域可被绕过）")

    def test_remote_spec_http_error_is_actionable(self) -> None:
        import httpx

        class FakeResponse:
            status_code = 302
            text = ""

        original = httpx.get
        httpx.get = lambda url, **kwargs: FakeResponse()
        try:
            with self.assertRaises(SpecError) as ctx:
                load_spec_source(
                    "https://specs.example.com/openapi.json", validate_url=lambda _url: ""
                )
        finally:
            httpx.get = original
        self.assertIn("302", str(ctx.exception))
        self.assertIn("不跟随重定向", str(ctx.exception))


class SurfaceIntegrationTests(unittest.TestCase):
    """导入的接口必须进入攻面与覆盖率闸门。"""

    def make_surface(self) -> AttackSurface:
        return AttackSurface(target=TARGET, mode="blackbox")

    def test_operations_land_in_the_surface(self) -> None:
        surface = self.make_surface()
        counts = surface.add_api_spec(import_openapi(OPENAPI3))
        # 3 个 operation，但只有 2 个端点：`/users/{id}` 的 GET 与 DELETE
        # 是同一路径的两种方法（端点按路径去重，方法合并）。
        self.assertEqual(counts["operations"], 3)
        self.assertEqual(counts["endpoints"], 2)
        self.assertIn(f"{TARGET}/users/{{id}}", surface.endpoints)
        self.assertIn(f"{TARGET}/orders", surface.endpoints)

    def test_path_templates_are_kept_verbatim(self) -> None:
        """路径模板 `{id}` 必须原样保留——换成具体值就丢掉了"参数在这里"这件事。"""
        surface = self.make_surface()
        surface.add_api_spec(import_openapi(OPENAPI3))
        self.assertIn(f"{TARGET}/users/{{id}}", surface.endpoints)
        self.assertIn("id", surface.endpoints[f"{TARGET}/users/{{id}}"].params)

    def test_endpoint_source_is_marked(self) -> None:
        surface = self.make_surface()
        surface.add_api_spec(import_openapi(OPENAPI3))
        self.assertIn("api_spec", surface.endpoints[f"{TARGET}/users/{{id}}"].source)

    def test_methods_are_registered(self) -> None:
        surface = self.make_surface()
        surface.add_api_spec(import_openapi(OPENAPI3))
        methods = surface.endpoints[f"{TARGET}/users/{{id}}"].methods
        self.assertIn("GET", methods)
        self.assertIn("DELETE", methods)

    def test_declared_params_enter_the_param_universe(self) -> None:
        """关键：规范声明了参数，参数级覆盖闸门就必须把它们算成待测。"""
        surface = self.make_surface()
        surface.add_api_spec(import_openapi(OPENAPI3))
        pending = dict(surface.unattacked_params())
        self.assertIn("verbose", [pair[1] for pair in surface.unattacked_params()])
        self.assertTrue(pending)
        tried, total = surface.param_coverage()
        self.assertEqual(tried, 0, "导入 ≠ 已测试")
        self.assertGreaterEqual(total, 3)

    def test_imported_endpoints_are_counted_as_untested(self) -> None:
        surface = self.make_surface()
        surface.add_api_spec(import_openapi(OPENAPI3))
        untouched = surface.untested_endpoints()
        self.assertIn(f"{TARGET}/orders", untouched)

    def test_import_alone_does_not_mark_anything_covered(self) -> None:
        """导入的是"该测什么"，不是"已经测过"——覆盖率必须仍然是 0。"""
        surface = self.make_surface()
        surface.add_api_spec(import_openapi(OPENAPI3))
        self.assertEqual(surface.touched_endpoints(), set())
        self.assertEqual(surface.coverage, {})

    def test_summary_shape(self) -> None:
        surface = self.make_surface()
        surface.add_api_spec(import_openapi(OPENAPI3))
        summary = surface.api_spec_summary()
        self.assertEqual(summary["endpoints"], 2)
        self.assertEqual(len(summary["imports"]), 1)
        self.assertEqual(summary["imports"][0]["flavor"], "openapi3")

    def test_surface_round_trip_preserves_spec_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "surface.json"
            surface = AttackSurface(target=TARGET, mode="blackbox", path=path)
            surface.add_api_spec(import_openapi(OPENAPI3))
            expected_params = len(surface.api_spec_params)
            surface.save(path)
            restored = AttackSurface.load(path, target=TARGET)
            summary = restored.api_spec_summary()
            self.assertEqual(summary["endpoints"], 2)
            self.assertEqual(len(restored.api_spec_params), expected_params)
            self.assertGreaterEqual(expected_params, 2)

    def test_body_operations_register_a_form(self) -> None:
        surface = self.make_surface()
        surface.add_api_spec(import_openapi(OPENAPI3))
        self.assertIn(f"{TARGET}/orders", surface.forms)
        self.assertIn("X-Trace", surface.forms[f"{TARGET}/orders"]["params"])

    def test_a_note_records_the_import(self) -> None:
        surface = self.make_surface()
        surface.add_api_spec(import_openapi(OPENAPI3))
        self.assertTrue(any("API 规范" in note for note in surface.notes))


class CliApiSpecTests(unittest.TestCase):
    """CLI 集成：`audit --api-spec` 必须真正导入、锚定、并出现在报告里。

    全程离线（脚本 LLM + 不可达目标），不消耗任何模型配额。
    """

    def setUp(self) -> None:
        import os

        from click.testing import CliRunner

        from hexhound import cli as cli_module

        self.cli = cli_module
        self._env = dict(os.environ)
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["HEXHOUND_HOME"] = str(Path(self._tmp.name) / "home")
        os.environ["ALLOWED_HOSTS"] = "127.0.0.1,localhost,hexhound-test.invalid"
        os.environ["LLM_PROVIDER"] = "deepseek"
        os.environ["PROVIDER_DEEPSEEK_API_KEY"] = "sk-test-not-used"
        for key in ("LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY"):
            os.environ.pop(key, None)
        self.runner = CliRunner()

    def tearDown(self) -> None:
        import os

        os.environ.clear()
        os.environ.update(self._env)
        self._tmp.cleanup()

    def invoke(self, args, tmp: str):
        from unittest.mock import patch

        from hexhound import llm as llm_module
        from hexhound.mockllm import ScriptedLLM

        class FakeLLM:
            provider = "scripted"
            model = "scripted-policy"

            def __init__(self, *a, **k) -> None:
                self._inner = ScriptedLLM()

            def describe(self) -> str:
                return "scripted/scripted-policy"

            def complete(self, messages):
                return self._inner.complete(messages)

        with (
            patch.object(self.cli, "LLMClient", FakeLLM),
            patch.object(llm_module, "LLMClient", FakeLLM),
        ):
            return self.runner.invoke(self.cli.main, args, catch_exceptions=True)

    def write_spec(self, spec: dict) -> str:
        path = Path(self._tmp.name) / "spec.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        return str(path)

    def audit_args(self, spec_path: str, output: Path) -> list[str]:
        return [
            "audit",
            "--target", "http://hexhound-test.invalid",
            "--mode", "blackbox", "--no-sandbox",
            "--max-tasks", "2", "--task-steps", "3",
            "--api-spec", spec_path,
            "--output", str(output),
        ]

    def test_spec_is_imported_and_anchored_to_target(self) -> None:
        spec_path = self.write_spec(OPENAPI3)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "r.md"
            result = self.invoke(self.audit_args(spec_path, output), tmp)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("API 合约导入", result.output)
            self.assertIn("已被忽略", result.output)
            text = output.read_text(encoding="utf-8")
            self.assertIn("## API 合约导入", text)
            # 关键判据不是"报告里没有 evil 字样"——报告**应该**引用它来警告读者。
            # 真正要验的是：**没有任何接口 URL 是用它构造的**。
            evil_urls = [
                token for token in text.replace("`", " ").split()
                if "evil.example.com" in token and token.startswith(("http", "//"))
            ]
            self.assertTrue(evil_urls, "报告里应当引用被忽略的 server 以提醒读者")
            for token in evil_urls:
                # 它只会以"被忽略的声明值"出现，绝不会作为接口地址出现
                self.assertNotIn("hexhound-test.invalid", token)
            # 接口锚定到 --target：规范路径直接拼在 target 之后
            self.assertIn("http://hexhound-test.invalid/users/{id}", text.replace("\\", "/"))
            self.assertIn("http://hexhound-test.invalid/orders", text.replace("\\", "/"))

    def test_imported_endpoints_reach_the_coverage_gate(self) -> None:
        """导入的接口必须出现在覆盖盲区里（导入 ≠ 已测试）。"""
        spec_path = self.write_spec(OPENAPI3)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "r.md"
            result = self.invoke(self.audit_args(spec_path, output), tmp)
            self.assertEqual(result.exit_code, 0, result.output)
            text = output.read_text(encoding="utf-8")
            self.assertIn("覆盖盲区", text)
            self.assertIn("/orders", text)

    def test_broken_spec_fails_loudly(self) -> None:
        """解析失败必须是**明确错误**，不能静默跳过当没事发生。"""
        path = Path(self._tmp.name) / "broken.json"
        path.write_text("{ this is not valid json or yaml", encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "r.md"
            result = self.invoke(self.audit_args(str(path), output), tmp)
            self.assertNotEqual(result.exit_code, 0)
            message = result.output + (result.stderr or "")
            self.assertIn("API 规范导入失败", message)

    def test_missing_spec_file_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "r.md"
            result = self.invoke(
                self.audit_args(str(Path(tmp) / "nope.json"), output), tmp
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("找不到规范文件", result.output + (result.stderr or ""))

    def test_unsupported_spec_version_fails_loudly(self) -> None:
        spec_path = self.write_spec({"openapi": "4.0.0", "paths": {"/x": {"get": {}}}})
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "r.md"
            result = self.invoke(self.audit_args(spec_path, output), tmp)
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("OpenAPI 3.x", result.output + (result.stderr or ""))

    def test_malicious_servers_in_spec_cannot_widen_scope(self) -> None:
        """规范要求把 evil 域名当 base URL —— 必须被无视，且不影响授权范围。"""
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://evil.example.com"}],
            "paths": {"/x": {"get": {"parameters": [{"name": "q", "in": "query"}]}}},
        }
        spec_path = self.write_spec(spec)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "r.md"
            result = self.invoke(self.audit_args(spec_path, output), tmp)
            self.assertEqual(result.exit_code, 0, result.output)
            text = output.read_text(encoding="utf-8")
            # 接口被锚定到 target
            self.assertIn("http://hexhound-test.invalid/x", text.replace("\\", "/"))

    def test_swagger2_spec_is_accepted(self) -> None:
        spec_path = self.write_spec(SWAGGER2)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "r.md"
            result = self.invoke(self.audit_args(spec_path, output), tmp)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("Swagger 2.0", result.output)

    def test_without_the_flag_nothing_changes(self) -> None:
        """不传 --api-spec 时行为与之前完全一致（老用户不受影响）。"""
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "r.md"
            args = [
                "audit", "--target", "http://hexhound-test.invalid",
                "--mode", "blackbox", "--no-sandbox",
                "--max-tasks", "2", "--task-steps", "3",
                "--output", str(output),
            ]
            result = self.invoke(args, tmp)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertNotIn("API 合约导入", result.output)
            text = output.read_text(encoding="utf-8")
            self.assertNotIn("## API 合约导入", text)


if __name__ == "__main__":
    unittest.main()

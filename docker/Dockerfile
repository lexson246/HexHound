# HexHound 沙箱镜像：把真工具装进一个可丢弃的容器里。
#
# 设计取舍（对标 Strix / PentAGI 的 Kali 镜像，但更小、约束更紧）：
# - 基于 Kali rolling：工具链齐全，省去自己编译
# - 只装 HexHound 会调用的工具（见 src/hexhound/sandbox.py 的 TOOL_ALLOWLIST）
# - 不装 Metasploit：HexHound 只做只读验证，不需要利用框架（省 1.5GB+）
# - 非 root 用户 + 无 capabilities：容器被攻破也拿不到实质权限
#
# 构建：
#   docker build -t hexhound-sandbox:latest docker/
# 或交给 HexHound 自己构建：
#   hexhound sandbox build

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:${PATH}"

# 只装需要的工具。nmap/fuff/nuclei/sqlmap/whatweb/nikto/gobuster + curl + python3
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        nmap \
        sqlmap \
        whatweb \
        nikto \
        gobuster \
        ffuf \
        python3 \
        python3-pip \
        jq \
        unzip \
        wordlists \
    && rm -rf /var/lib/apt/lists/*

# nuclei 从官方发布装（apt 里没有）
ARG NUCLEI_VERSION=3.3.7
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) nuclei_arch="amd64" ;; \
      arm64) nuclei_arch="arm64" ;; \
      *) nuclei_arch="amd64" ;; \
    esac; \
    url="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${nuclei_arch}.zip"; \
    if wget -q -O /tmp/nuclei.zip "$url"; then \
        unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei && rm -f /tmp/nuclei.zip; \
    else \
        echo "nuclei 下载失败（离线构建？），跳过"; \
    fi; \
    chmod +x /usr/local/bin/nuclei 2>/dev/null || true

# 非 root 用户：容器内不给自己留提权面
RUN useradd -m -u 10001 -s /bin/bash hunter \
    && mkdir -p /work \
    && chown -R hunter:hunter /work
USER hunter
WORKDIR /work

# 保活入口：命令通过 `docker exec` 进来（与 Strix / PentAGI 同样的常驻方式）
ENTRYPOINT ["sh"]
CMD ["-c", "tail -f /dev/null"]

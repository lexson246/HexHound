"""多模态视觉客户端：把截图交给 qwen3-vl 等视觉模型分析。"""
from __future__ import annotations

import base64
from typing import Any

from openai import OpenAI

Message = dict[str, Any]


class VisionClient:
    """对 openai.OpenAI 的薄封装，用于图片 → 文本的多模态分析。"""

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        temperature: float = 0.2,
    ) -> None:
        self._model = model
        self._temperature = temperature
        self._client = OpenAI(api_key=api_key, base_url=base_url or None)

    def analyze(self, image_bytes: bytes, mime_type: str, question: str) -> str:
        """分析一张图片，返回模型回答文本。"""
        encoded = base64.b64encode(image_bytes).decode("ascii")
        data_url = f"data:{mime_type or 'image/png'};base64,{encoded}"
        messages: list[Message] = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": question or "请描述这张图片。"},
                    {"type": "image_url", "image_url": {"url": data_url}},
                ],
            }
        ]
        response = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=self._temperature,
        )
        return response.choices[0].message.content or ""

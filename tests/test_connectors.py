"""Connectors: request shaping, response parsing, retries, rate limiting, secret masking."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from scanner.connectors import (
    CallableConnector,
    PolicyConnector,
    RateLimiter,
    RetryPolicy,
    build_connector,
    parse_target,
)
from scanner.connectors.http import HTTPConnector, parse_sse, render_template
from scanner.models import Message, TargetResponse
from scanner.probes import ToolDef

U = Message(role="user", content="hello")


def transport(handler):
    return httpx.MockTransport(handler)


def http_cfg(**kw):
    return parse_target({"type": "http", "url": "http://t/chat", "response_path": "$.reply", **kw})


# ------------------------------------------------------------------------------ HTTP


async def test_http_template_headers_auth_and_reply():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers["authorization"]
        seen["x"] = request.headers["x-tenant"]
        return httpx.Response(
            200,
            json={
                "reply": "pong",
                "tool_calls": [{"name": "send_email", "arguments": {"to": "a@b.c"}}],
                "sid": "S-1",
            },
        )

    cfg = http_cfg(
        headers={"X-Tenant": "acme"},
        auth={"type": "bearer", "token": "sekret-token-123"},
        body={"message": "{{prompt}}", "session": "{{conversation_id}}", "n": 1},
        tool_calls_path="$.tool_calls",
        conversation_id_path="$.sid",
    )
    c = HTTPConnector(cfg, transport=transport(handler))
    resp = await c.send([Message(role="system", content="SYS"), U], conversation_id="c1")
    assert resp.text == "pong" and resp.ok
    assert seen["body"] == {"message": "hello", "session": "c1", "n": 1}
    assert seen["auth"] == "Bearer sekret-token-123" and seen["x"] == "acme"
    assert resp.tool_calls[0].name == "send_email" and resp.tool_calls[0].arguments == {
        "to": "a@b.c"
    }
    # the server-issued id is used on the next turn of the same conversation
    await c.send([U], conversation_id="c1")
    assert seen["body"]["session"] == "S-1"
    await c.aclose()


async def test_http_messages_placeholder_keeps_types_and_sets_history_flag():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"reply": "ok"})

    c = HTTPConnector(
        http_cfg(body={"messages": "{{messages}}", "system": "{{system}}"}),
        transport=transport(handler),
    )
    assert c.supports_history is True
    await c.send(
        [
            Message(role="system", content="S"),
            U,
            Message(role="assistant", content="a"),
            Message(role="user", content="b"),
        ]
    )
    assert seen["body"]["messages"][-1] == {"role": "user", "content": "b"}
    assert seen["body"]["system"] == "S"
    assert HTTPConnector(http_cfg(), transport=transport(handler)).supports_history is False


async def test_http_wrong_response_path_is_a_clear_error_not_an_exception():
    c = HTTPConnector(
        http_cfg(response_path="$.nope"),
        transport=transport(lambda r: httpx.Response(200, json={"reply": "x"})),
    )
    resp = await c.send([U])
    assert resp.error and "response_path" in resp.error and "reply" in resp.error


async def test_http_non_json_and_text_and_sse_modes():
    c = HTTPConnector(
        http_cfg(), transport=transport(lambda r: httpx.Response(200, text="<html>oops</html>"))
    )
    assert "not JSON" in (await c.send([U])).error
    c = HTTPConnector(
        http_cfg(response_format="text"),
        transport=transport(lambda r: httpx.Response(200, text="plain")),
    )
    assert (await c.send([U])).text == "plain"
    sse = 'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\ndata: {"choices":[{"delta":{"content":"lo"}}]}\n\ndata: [DONE]\n'
    assert parse_sse(sse, "$.choices[0].delta.content") == "Hello"


async def test_http_get_form_and_query():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"reply": "ok"})

    c = HTTPConnector(
        http_cfg(method="GET", query={"q": "{{prompt}}"}), transport=transport(handler)
    )
    await c.send([U])
    assert "q=hello" in seen["url"]
    c = HTTPConnector(
        http_cfg(body_format="form", body={"text": "{{prompt}}"}), transport=transport(handler)
    )
    await c.send([U])
    assert seen["body"] == "text=hello"


@pytest.mark.parametrize(
    ("status", "retryable"),
    [(429, True), (500, True), (503, True), (400, False), (401, False), (404, False)],
)
async def test_http_error_classification(status, retryable):
    c = HTTPConnector(
        http_cfg(),
        transport=transport(
            lambda r: httpx.Response(status, text="nope", headers={"Retry-After": "2"})
        ),
    )
    resp = await c.send([U])
    assert resp.error and f"HTTP {status}" in resp.error
    assert bool(resp.meta.get("retryable")) is retryable
    if status == 429:
        assert resp.meta["retry_after"] == 2.0


async def test_http_timeout_and_connection_errors_are_retryable():
    def boom(request):
        raise httpx.ConnectTimeout("slow", request=request)

    resp = await HTTPConnector(http_cfg(), transport=transport(boom)).send([U])
    assert "timeout" in resp.error and resp.meta["retryable"]

    def refuse(request):
        raise httpx.ConnectError("refused", request=request)

    resp = await HTTPConnector(http_cfg(), transport=transport(refuse)).send([U])
    assert "connection error" in resp.error and resp.meta["retryable"]


def test_render_template_types():
    v = {"prompt": "p", "messages": [{"role": "user", "content": "p"}], "none": None}
    assert render_template("{{messages}}", v) == v["messages"]
    assert render_template({"a": ["{{prompt}}", 1]}, v) == {"a": ["p", 1]}
    assert render_template("x {{messages}} y", v).startswith("x [{")
    assert render_template("{{unknown}}", v) == "{{unknown}}"


def test_describe_never_leaks_credentials():
    c = HTTPConnector(
        http_cfg(
            auth={"type": "bearer", "token": "supersecrettoken"},
            headers={"X-Api-Key": "abcdef123456"},
        )
    )
    blob = json.dumps(c.describe())
    assert "supersecrettoken" not in blob and "abcdef123456" not in blob


# ---------------------------------------------------------------------- providers


async def test_openai_request_and_response_shapes():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers["authorization"]
        seen["url"] = str(request.url)
        return httpx.Response(
            200,
            json={
                "model": "m",
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "1",
                                    "type": "function",
                                    "function": {
                                        "name": "delete_file",
                                        "arguments": '{"path": "/tmp/x"}',
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"total_tokens": 3},
            },
        )

    c = build_connector(
        {
            "type": "openai_compat",
            "base_url": "http://llm/v1",
            "api_key": "k-123456789",
            "model": "m",
            "max_tokens": 50,
            "temperature": 0,
        },
        transport=transport(handler),
    )
    tool = ToolDef(
        name="delete_file",
        description="d",
        parameters={"type": "object", "properties": {"path": {"type": "string"}}},
    )
    resp = await c.send([Message(role="system", content="S"), U], tools=[tool])
    assert seen["url"] == "http://llm/v1/chat/completions" and seen["auth"] == "Bearer k-123456789"
    assert seen["body"]["messages"][0] == {"role": "system", "content": "S"}
    assert seen["body"]["max_tokens"] == 50 and seen["body"]["temperature"] == 0
    assert seen["body"]["tools"][0]["function"]["name"] == "delete_file"
    assert resp.tool_calls[0].name == "delete_file" and resp.tool_calls[0].arguments == {
        "path": "/tmp/x"
    }
    assert "k-123456789" not in json.dumps(c.describe())


async def test_openai_content_parts_and_refusal_field():
    for message, expected in [
        ({"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}, "ab"),
        ({"content": None, "refusal": "I can't help"}, "I can't help"),
    ]:
        c = build_connector(
            {"type": "openai", "model": "m", "api_key": "x"},
            transport=transport(
                lambda r, m=message: httpx.Response(200, json={"choices": [{"message": m}]})
            ),
        )
        assert (await c.send([U])).text == expected


async def test_openai_max_completion_tokens_param_and_bad_shape():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"unexpected": True})

    c = build_connector(
        {
            "type": "openai",
            "model": "o",
            "api_key": "x",
            "max_tokens_param": "max_completion_tokens",
            "max_tokens": 9,
        },
        transport=transport(handler),
    )
    resp = await c.send([U])
    assert seen["body"]["max_completion_tokens"] == 9 and "max_tokens" not in seen["body"]
    assert resp.error and "unexpected response shape" in resp.error


async def test_anthropic_shapes():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        seen["h"] = dict(request.headers)
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "hi"},
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "send_email",
                        "input": {"to": "x@y.z"},
                    },
                ],
                "stop_reason": "tool_use",
            },
        )

    c = build_connector(
        {"type": "anthropic", "model": "claude", "api_key": "sk-ant-abcdefghijklmnop"},
        transport=transport(handler),
    )
    msgs = [
        Message(role="system", content="S1"),
        Message(role="system", content="S2"),
        U,
        Message(role="user", content="second"),
        Message(role="assistant", content="a"),
    ]
    resp = await c.send(
        msgs, tools=[ToolDef(name="send_email", parameters={"type": "object", "properties": {}})]
    )
    b = seen["body"]
    assert b["system"] == "S1\n\nS2"
    assert b["messages"][0] == {
        "role": "user",
        "content": "hello\n\nsecond",
    }  # consecutive user turns merged
    assert b["messages"][-1]["role"] == "assistant"
    assert (
        b["tools"][0]["input_schema"]
        and seen["h"]["x-api-key"].startswith("sk-ant")
        and "anthropic-version" in seen["h"]
    )
    assert resp.text == "hi" and resp.tool_calls[0].arguments == {"to": "x@y.z"}


async def test_ollama_shapes():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": "yo",
                    "tool_calls": [
                        {"function": {"name": "run_shell", "arguments": {"command": "ls"}}}
                    ],
                },
                "eval_count": 5,
            },
        )

    c = build_connector(
        {"type": "ollama", "model": "llama3", "options": {"temperature": 0}},
        transport=transport(handler),
    )
    resp = await c.send([U], tools=[ToolDef(name="run_shell")])
    assert seen["body"]["stream"] is False and seen["body"]["options"] == {"temperature": 0}
    assert (
        resp.text == "yo"
        and resp.tool_calls[0].arguments == {"command": "ls"}
        and resp.usage["completion_tokens"] == 5
    )


def test_target_config_validation():
    with pytest.raises(ValueError):
        parse_target({"type": "http"})  # url is required
    with pytest.raises(ValueError):
        parse_target({"type": "http", "url": "x", "bogus": 1})  # unknown key
    t = parse_target({"type": "http", "url": "x", "canaries": ["A" * 12, "B" * 12]})
    assert set(t.canaries) == {"canary", "canary_2"}


# ------------------------------------------------------------------- policy wrapper


async def test_policy_retries_then_gives_up(monkeypatch):
    calls = {"n": 0}

    async def fake_sleep(_):
        return None

    def flaky(_msgs):
        calls["n"] += 1
        if calls["n"] < 3:
            return TargetResponse(error="HTTP 503", meta={"retryable": True})
        return TargetResponse(text="finally")

    p = PolicyConnector(
        CallableConnector(flaky), retry=RetryPolicy(max_retries=3), sleep=fake_sleep
    )
    resp = await p.send([U])
    assert resp.text == "finally" and resp.meta["attempts"] == 3 and p.total_retries == 2

    calls["n"] = -100
    p = PolicyConnector(
        CallableConnector(flaky), retry=RetryPolicy(max_retries=2), sleep=fake_sleep
    )
    resp = await p.send([U])
    assert resp.error and resp.meta["attempts"] == 3


async def test_policy_does_not_retry_permanent_errors():
    n = {"c": 0}

    def fn(_):
        n["c"] += 1
        return TargetResponse(error="HTTP 401", meta={"retryable": False})

    p = PolicyConnector(CallableConnector(fn), retry=RetryPolicy(max_retries=5))
    await p.send([U])
    assert n["c"] == 1


async def test_retry_after_is_honoured():
    delays = []

    async def fake_sleep(d):
        delays.append(d)

    seq = iter(
        [
            TargetResponse(error="429", meta={"retryable": True, "retry_after": 7}),
            TargetResponse(text="ok"),
        ]
    )
    p = PolicyConnector(CallableConnector(lambda _: next(seq)), sleep=fake_sleep)
    await p.send([U])
    assert delays == [7]


async def test_rate_limiter_spaces_requests():
    now = {"t": 0.0}
    slept = []

    async def fake_sleep(d):
        slept.append(d)
        now["t"] += d

    rl = RateLimiter(4.0, clock=lambda: now["t"], sleep=fake_sleep)  # 4 rps -> 0.25 s apart
    for _ in range(4):
        await rl.acquire()
    assert slept == pytest.approx([0.25, 0.25, 0.25])
    assert RateLimiter(None).interval == 0


async def test_concurrency_is_capped():
    active = {"now": 0, "max": 0}

    class Slow(CallableConnector):
        async def send(self, messages, **kw):
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
            await asyncio.sleep(0.02)
            active["now"] -= 1
            return TargetResponse(text="x")

    p = PolicyConnector(Slow(lambda m: ""), concurrency=3)
    await asyncio.gather(*(p.send([U]) for _ in range(12)))
    assert active["max"] == 3


async def test_callable_connector_wraps_exceptions():
    def bad(_):
        raise RuntimeError("kaput")

    resp = await CallableConnector(bad).send([U])
    assert "RuntimeError: kaput" in resp.error

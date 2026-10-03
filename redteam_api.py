#!/usr/bin/env python3
"""红队工具引擎 API — 精简适配版"""
import json, os, time, subprocess, re as _re
from pathlib import Path
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

BASE = Path(__file__).parent
load_dotenv(BASE / ".env", override=True)

DEEPSEEK_API = os.getenv("DEEPSEEK_API", "https://api.deepseek.com/v1")
DEEPSEEK_KEY = os.getenv("DEEPSEEK_API_KEY", "")
MODEL_UP = "deepseek-chat"
KEYS_F = BASE / "assistant_api_keys.json"

app = FastAPI(title="redteam-api")

TOOLS = [
 {"type":"function","function":{"name":"sh","description":"Run shell command","parameters":{"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"]}}},
 {"type":"function","function":{"name":"read","description":"Read file","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}},
 {"type":"function","function":{"name":"write","description":"Write file","parameters":{"type":"object","properties":{"path":{"type":"string"},"text":{"type":"string"}},"required":["path","text"]}}},
 {"type":"function","function":{"name":"edit","description":"Replace text in file","parameters":{"type":"object","properties":{"path":{"type":"string"},"old":{"type":"string"},"new":{"type":"string"}},"required":["path","old","new"]}}},
 {"type":"function","function":{"name":"url","description":"Fetch webpage or POST","parameters":{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string"},"data":{"type":"string"},"cookie":{"type":"string"}},"required":["url"]}}},
 {"type":"function","function":{"name":"search","description":"Web search","parameters":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}}},
 {"type":"function","function":{"name":"fofa","description":"FOFA asset search","parameters":{"type":"object","properties":{"q":{"type":"string"},"limit":{"type":"integer"}},"required":["q"]}}},
 {"type":"function","function":{"name":"get_current_time","description":"Get current time","parameters":{"type":"object","properties":{"tz":{"type":"string"}},"required":["tz"]}}},
 {"type":"function","function":{"name":"http_burst","description":"并发HTTP请求(竞态测试): url method data headers(JSON) n并发数","parameters":{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string"},"data":{"type":"string"},"headers":{"type":"string"},"n":{"type":"integer"}},"required":["url"]}}},
 {"type":"function","function":{"name":"jwt_decode","description":"解析JWT(不验签)","parameters":{"type":"object","properties":{"token":{"type":"string"}},"required":["token"]}}},
 {"type":"function","function":{"name":"jwt_forge","description":"伪造JWT: payload(JSON) secret(留空试none) alg","parameters":{"type":"object","properties":{"payload":{"type":"string"},"secret":{"type":"string"},"alg":{"type":"string"}},"required":["payload"]}}},
]

_SHELL = dict(env={**os.environ, "PYTHONIOENCODING": "utf-8"})

def _sub(cmd, timeout=120):
    try:
        p = subprocess.run(
            f"timeout {timeout} bash -c '{cmd.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}' </dev/null",
            shell=True, capture_output=True, text=True, timeout=timeout + 15,
            cwd=str(BASE), **_SHELL)
        return (p.stdout or "")[:8000] or (p.stderr or "")[:1000] or "Done"
    except Exception as e:
        return f"[执行异常] {type(e).__name__}: {e}"

def _exec_tool(name, args, uid=0):
    try:
        a = args or {}
        if name == "sh":
            return _sub(str(a.get("cmd", "")).strip())
        if name == "read":
            p = a["path"]
            if not p.startswith("/"): p = str(BASE / p)
            if not os.path.isfile(p): return f"❌ 不存在: {p}"
            with open(p) as f: return f.read()[:8000]
        if name == "write":
            p = a["path"]
            if not p.startswith("/"): p = str(BASE / p)
            tx = a.get("text") or a.get("content") or ""
            if not tx: return "❌ 内容为空"
            os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
            with open(p, "w") as f: f.write(tx)
            return f"OK {len(tx)}b"
        if name == "edit":
            p = a["path"]
            if not p.startswith("/"): p = str(BASE / p)
            if not os.path.isfile(p): return f"❌ 不存在: {p}"
            with open(p) as f: c = f.read()
            if a["old"] not in c: return "NotFound"
            with open(p, "w") as f: f.write(c.replace(a["old"], a["new"], 1))
            return "Done"
        if name == "url":
            url = a.get("url", ""); method = a.get("method", "GET").upper()
            data = a.get("data", ""); cookie = a.get("cookie", "")
            h = {"User-Agent": "Mozilla/5.0"}
            if cookie: h["Cookie"] = cookie
            r = httpx.request(method, url, content=data.encode() if data else None,
                              headers=h, timeout=20, follow_redirects=True)
            return r.text[:6000]
        if name == "search":
            try:
                from duckduckgo_search import DDGS
                with DDGS() as d:
                    return "\n".join(f"{x['title']}\n{x['href']}" for x in d.text(a.get("q", ""), max_results=5))[:4000]
            except Exception as e:
                return f"Search fail: {e}"
        if name == "fofa":
            q = a.get("q", ""); limit = min(int(a.get("limit", 20) or 20), 100)
            if not q: return "fofa: 需要 q"
            fe = os.getenv("FOFA_EMAIL", ""); fk = os.getenv("FOFA_API_KEY", "")
            if not fe or not fk: return "fofa: 未配置 FOFA_EMAIL/FOFA_API_KEY"
            import base64, urllib.parse
            qb64 = base64.b64encode(q.encode()).decode()
            u = f"https://fofa.info/api/v1/search/all?email={urllib.parse.quote(fe)}&key={fk}&qbase64={qb64}&size={limit}&fields=host,ip,port,title"
            r = httpx.get(u, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
            d = r.json()
            if d.get("error"): return f"err: {d.get('errmsg')}"
            res = d.get("results", [])
            return "\n".join(f"{x[0]} | {x[1]}:{x[2]} | {str(x[3])[:50]}" for x in res) or "无结果"
        if name == "get_current_time":
            import datetime as dt
            tz = a.get("tz", "Asia/Shanghai")
            try:
                from zoneinfo import ZoneInfo
                now = dt.datetime.now(ZoneInfo(tz))
            except Exception:
                now = dt.datetime.utcnow()
            return now.strftime("%Y-%m-%d %H:%M:%S") + f" ({tz})"
        if name == "http_burst":
            import threading
            from collections import Counter
            url = a.get("url", ""); method = a.get("method", "GET").upper()
            n = min(int(a.get("n", 20)), 200)
            data = a.get("data", "")
            try:
                hdrs = json.loads(a.get("headers", "") or "{}")
            except Exception:
                hdrs = {}
            results = []
            lock = threading.Lock()
            def _one():
                try:
                    r = httpx.request(method, url, content=data.encode() if data else None,
                                      headers=hdrs, timeout=15, follow_redirects=True)
                    with lock: results.append((r.status_code, len(r.content), r.text[:150]))
                except Exception as e:
                    with lock: results.append(("ERR", 0, str(e)[:80]))
            ths = [threading.Thread(target=_one) for _ in range(n)]
            t0 = time.time()
            for t in ths: t.start()
            for t in ths: t.join()
            el = time.time() - t0
            codes = Counter(r[0] for r in results)
            sizes = Counter(r[1] for r in results)
            return f"并发{n} 耗时{el:.2f}s\n状态码: {dict(codes)}\n响应大小: {dict(sizes)}\n前3样本:\n" + "\n".join(repr(r) for r in results[:3])
        if name == "jwt_decode":
            import base64
            tok = a.get("token", "").strip()
            ps = tok.split(".")
            if len(ps) != 3: return "❌ 不是有效 JWT"
            def _d(s):
                s += "=" * (-len(s) % 4)
                return base64.urlsafe_b64decode(s).decode("utf-8", "replace")
            return f"HEADER: {_d(ps[0])}\nPAYLOAD: {_d(ps[1])}\nSIG: {ps[2][:80]}"
        if name == "jwt_forge":
            try:
                payload = json.loads(a.get("payload", "{}"))
            except Exception as e:
                return f"❌ payload 不合法: {e}"
            secret = a.get("secret", ""); alg = a.get("alg", "HS256")
            try:
                import jwt as _j
                tok = _j.encode(payload, "", algorithm="none") if (alg.lower() == "none" or not secret) else _j.encode(payload, secret, algorithm=alg)
                return f"FORGED: {tok}"
            except ImportError:
                return "❌ pyjwt 未安装"
            except Exception as e:
                return f"失败: {e}"
    except Exception as e:
        return f"[工具错误] {type(e).__name__}: {str(e)[:300]}"
    return f"[未知工具 {name}]"

def _agent_loop(uid, messages, max_round=8):
    cur = list(messages)
    for _ in range(max_round):
        r = httpx.post(f"{DEEPSEEK_API}/chat/completions",
                       headers={"Authorization": f"Bearer {DEEPSEEK_KEY}", "Content-Type": "application/json"},
                       json={"model": MODEL_UP, "messages": cur, "tools": TOOLS, "max_tokens": 2048, "stream": False},
                       timeout=240)
        if r.status_code != 200:
            return cur, r.text[:300], None
        msg = r.json()["choices"][0]["message"]
        tcs = msg.get("tool_calls")
        if not tcs:
            return cur, None, msg
        cur.append(msg)
        for tc in tcs:
            if not isinstance(tc, dict): continue
            try:
                args = json.loads(tc["function"].get("arguments", "{}") or "{}")
            except Exception:
                args = {}
            res = _exec_tool(tc["function"]["name"], args, uid)
            cur.append({"role": "tool", "tool_call_id": tc.get("id") or f"call_{time.time():.0f}", "content": res[:3000]})
    return cur, "TOOL_LOOP_MAX", None

SYSTEM_PROMPT = "你是红队执行器。只对授权目标执行操作。需要动手的任务直接调用工具, 干完用结果说话。"

def _auth(auth):
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    k = auth[7:].strip()
    try:
        m = json.loads(KEYS_F.read_text(encoding="utf-8"))
    except Exception:
        m = {}
    if k not in m:
        raise HTTPException(401, "Invalid key")
    return int(m[k])

@app.get("/v1/health")
async def health():
    return {"ok": True, "ts": int(time.time())}

@app.post("/v1/chat/completions")
async def chat(request: Request):
    uid = _auth(request.headers.get("authorization"))
    body = await request.json()
    messages = body.get("messages") or []
    if not messages:
        raise HTTPException(400, "messages required")
    if len(messages) > 20: messages = messages[-20:]
    full = [{"role": "system", "content": SYSTEM_PROMPT}] + messages
    cur, err, final = _agent_loop(uid, full)
    if final is not None:
        return JSONResponse({"id": f"chatcmpl-{uid}", "object": "chat.completion", "created": int(time.time()),
                             "model": "redteam", "choices": [{"index": 0, "message": final, "finish_reason": "stop"}]})
    return JSONResponse({"id": f"chatcmpl-{uid}", "object": "chat.completion", "created": int(time.time()),
        "model": "redteam", "choices": [{"index": 0, "message": {"role": "assistant", "content": f"[循环终止] {err}"}, "finish_reason": "stop"}]})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8894)), log_level="warning")

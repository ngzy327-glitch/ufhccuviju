#!/usr/bin/env python3
"""红队工具引擎 — 防循环版"""
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

TOOLS_WHALE = [
 {"type":"function","function":{"name":"sh","description":"Run shell command","parameters":{"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"]}}},
 {"type":"function","function":{"name":"read","description":"Read file","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}},
 {"type":"function","function":{"name":"write","description":"Write file","parameters":{"type":"object","properties":{"path":{"type":"string"},"text":{"type":"string"}},"required":["path","text"]}}},
 {"type":"function","function":{"name":"edit","description":"Replace text in file","parameters":{"type":"object","properties":{"path":{"type":"string"},"old":{"type":"string"},"new":{"type":"string"}},"required":["path","old","new"]}}},
 {"type":"function","function":{"name":"url","description":"Fetch webpage or POST","parameters":{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string"},"data":{"type":"string"},"cookie":{"type":"string"}},"required":["url"]}}},
 {"type":"function","function":{"name":"search","description":"Web search","parameters":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}}},
 {"type":"function","function":{"name":"fofa","description":"FOFA asset search","parameters":{"type":"object","properties":{"q":{"type":"string"},"limit":{"type":"integer"}},"required":["q"]}}},
 {"type":"function","function":{"name":"get_current_time","description":"Get current time","parameters":{"type":"object","properties":{"tz":{"type":"string"}},"required":["tz"]}}},
 {"type":"function","function":{"name":"http_burst","description":"并发HTTP: url method data headers n","parameters":{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string"},"data":{"type":"string"},"headers":{"type":"string"},"n":{"type":"integer"}},"required":["url"]}}},
 {"type":"function","function":{"name":"jwt_decode","description":"解析JWT","parameters":{"type":"object","properties":{"token":{"type":"string"}},"required":["token"]}}},
 {"type":"function","function":{"name":"jwt_forge","description":"伪造JWT: payload secret alg","parameters":{"type":"object","properties":{"payload":{"type":"string"},"secret":{"type":"string"},"alg":{"type":"string"}},"required":["payload"]}}},
]

_SHELL = dict(env={**os.environ, "PYTHONIOENCODING": "utf-8"})

def _sub(cmd, timeout=60):
    """改进版: 明确区分 stdout/stderr/超时, 防止AI误判重试"""
    try:
        p = subprocess.run(
            f"timeout {timeout} bash -c '{cmd.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}' </dev/null",
            shell=True, capture_output=True, text=True, timeout=timeout + 10,
            cwd=str(BASE), **_SHELL)
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        if out and len(out) > 3:
            return out[:8000]
        if err and len(err) > 3:
            return f"[FAIL-STOP] 命令报错, 不要重试: {err[:800]}"
        return "[命令执行完成, 无输出. 不要重试, 直接汇报]"
    except subprocess.TimeoutExpired:
        return f"[FAIL-STOP] 命令超时{timeout}s已终止, 不要重试, 换个方法或汇报失败"
    except Exception as e:
        return f"[FAIL-STOP] 执行异常: {type(e).__name__}: {e}, 不要重试"

def _exec_tool(name, args, uid=0):
    try:
        a = args or {}
        if name == "sh":
            return _sub(str(a.get("cmd", "")).strip())
        if name == "read":
            p = a["path"]
            if not p.startswith("/"): p = str(BASE / p)
            if not os.path.isfile(p): return f"[FAIL-STOP] 文件不存在: {p}"
            with open(p) as f: return f.read()[:8000]
        if name == "write":
            p = a["path"]
            if not p.startswith("/"): p = str(BASE / p)
            tx = a.get("text") or a.get("content") or ""
            if not tx: return "[FAIL-STOP] 内容为空"
            os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
            with open(p, "w") as f: f.write(tx)
            return f"OK 写入 {len(tx)} 字节到 {p}"
        if name == "edit":
            p = a["path"]
            if not p.startswith("/"): p = str(BASE / p)
            if not os.path.isfile(p): return f"[FAIL-STOP] 文件不存在: {p}"
            with open(p) as f: c = f.read()
            if a["old"] not in c: return "[FAIL-STOP] 没找到要替换的内容, 不要重试"
            with open(p, "w") as f: f.write(c.replace(a["old"], a["new"], 1))
            return "Done"
        if name == "url":
            url = a.get("url", ""); method = a.get("method", "GET").upper()
            data = a.get("data", ""); cookie = a.get("cookie", "")
            h = {"User-Agent": "Mozilla/5.0"}
            if cookie: h["Cookie"] = cookie
            try:
                r = httpx.request(method, url, content=data.encode() if data else None,
                                  headers=h, timeout=15, follow_redirects=True)
                return f"状态码 {r.status_code}, 长度 {len(r.content)}\n{r.text[:5000]}"
            except Exception as e:
                return f"[FAIL-STOP] 请求失败, 不要重试: {type(e).__name__}: {e}"
        if name == "search":
            try:
                from duckduckgo_search import DDGS
                with DDGS() as d:
                    return "\n".join(f"{x['title']}\n{x['href']}" for x in d.text(a.get("q", ""), max_results=5))[:4000]
            except Exception as e:
                return f"[FAIL-STOP] 搜索失败: {e}"
        if name == "fofa":
            q = a.get("q", ""); limit = min(int(a.get("limit", 20) or 20), 100)
            if not q: return "[FAIL-STOP] 缺少 q 参数"
            fe = os.getenv("FOFA_EMAIL", ""); fk = os.getenv("FOFA_API_KEY", "")
            if not fe or not fk: return "[FAIL-STOP] 未配置 FOFA_EMAIL/FOFA_API_KEY"
            import base64, urllib.parse
            qb64 = base64.b64encode(q.encode()).decode()
            u = f"https://fofa.info/api/v1/search/all?email={urllib.parse.quote(fe)}&key={fk}&qbase64={qb64}&size={limit}&fields=host,ip,port,title"
            try:
                r = httpx.get(u, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
                d = r.json()
                if d.get("error"): return f"[FAIL-STOP] FOFA错误: {d.get('errmsg')}"
                res = d.get("results", [])
                return "\n".join(f"{x[0]} | {x[1]}:{x[2]} | {str(x[3])[:50]}" for x in res) or "[无结果, 不要重试]"
            except Exception as e:
                return f"[FAIL-STOP] FOFA请求失败: {e}"
        if name == "get_current_time":
            import datetime as dt
            tz = a.get("tz", "Asia/Shanghai")
            try:
                from zoneinfo import ZoneInfo
                now = dt.datetime.now(ZoneInfo(tz))
            except Exception:
                now = dt.datetime.utcnow()
            return now.strftime("%Y-%m-%d %H:%M:%S")
        if name == "http_burst":
            import threading
            from collections import Counter
            url = a.get("url", ""); method = a.get("method", "GET").upper()
            n = min(int(a.get("n", 20)), 100)
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
                                      headers=hdrs, timeout=10, follow_redirects=True)
                    with lock: results.append((r.status_code, len(r.content)))
                except Exception as e:
                    with lock: results.append(("ERR", 0))
            ths = [threading.Thread(target=_one) for _ in range(n)]
            for t in ths: t.start()
            for t in ths: t.join()
            codes = Counter(r[0] for r in results)
            sizes = Counter(r[1] for r in results)
            return f"并发{n} 完成\n状态码分布: {dict(codes)}\n响应大小分布: {dict(sizes)}"
        if name == "jwt_decode":
            import base64
            tok = a.get("token", "").strip()
            ps = tok.split(".")
            if len(ps) != 3: return "[FAIL-STOP] 不是有效JWT"
            def _d(s):
                s += "=" * (-len(s) % 4)
                return base64.urlsafe_b64decode(s).decode("utf-8", "replace")
            try:
                return f"HEADER: {_d(ps[0])}\nPAYLOAD: {_d(ps[1])}\nSIG: {ps[2][:80]}"
            except Exception as e:
                return f"[FAIL-STOP] 解析失败: {e}"
        if name == "jwt_forge":
            try:
                payload = json.loads(a.get("payload", "{}"))
            except Exception as e:
                return f"[FAIL-STOP] payload 不合法: {e}"
            secret = a.get("secret", ""); alg = a.get("alg", "HS256")
            try:
                import jwt as _j
                tok = _j.encode(payload, "", algorithm="none") if (alg.lower() == "none" or not secret) else _j.encode(payload, secret, algorithm=alg)
                return f"FORGED: {tok}"
            except ImportError:
                return "[FAIL-STOP] pyjwt 未安装"
            except Exception as e:
                return f"[FAIL-STOP] 失败: {e}"
    except Exception as e:
        return f"[FAIL-STOP] 工具错误: {type(e).__name__}: {str(e)[:200]}"
    return f"[FAIL-STOP] 未知工具 {name}"

# ===== 防循环核心: 重复调用检测 =====
def _agent_loop(uid, messages, max_round=5):
    """最多5轮, 重复工具+参数立即终止"""
    cur = list(messages)
    recent_sigs = []
    for _ in range(max_round):
        r = httpx.post(f"{DEEPSEEK_API}/chat/completions",
                       headers={"Authorization": f"Bearer {DEEPSEEK_KEY}", "Content-Type": "application/json"},
                       json={"model": MODEL_UP, "messages": cur, "tools": TOOLS_WHALE, "max_tokens": 2048, "stream": False},
                       timeout=180)
        if r.status_code != 200:
            return cur, r.text[:300], None
        msg = r.json()["choices"][0]["message"]
        tcs = msg.get("tool_calls")
        if not tcs:
            return cur, None, msg
        cur.append(msg)
        for tc in tcs:
            if not isinstance(tc, dict): continue
            # 重复调用签名检测
            sig = (tc.get("function", {}).get("name", ""), tc.get("function", {}).get("arguments", ""))
            if sig in recent_sigs:
                return cur, None, {"role": "assistant", "content": "[检测到重复调用同一工具+参数, 已自动停止。请换个思路或重新描述任务。]"}
            recent_sigs.append(sig)
            if len(recent_sigs) > 4: recent_sigs.pop(0)
            try:
                args = json.loads(tc["function"].get("arguments", "{}") or "{}")
            except Exception:
                args = {}
            res = _exec_tool(tc["function"]["name"], args, uid)
            cur.append({"role": "tool", "tool_call_id": tc.get("id") or f"call_{time.time():.0f}", "content": res[:3000]})
    return cur, None, {"role": "assistant", "content": "[已达最大工具轮数5轮, 自动停止。请检查任务是否明确。]"}

SYSTEM_PROMPT = (
    "你是红队执行器。只对授权目标执行操作。"
    "工具返回以 [FAIL-STOP] 开头时, 表示路径已封死, 必须立刻停止重试并汇报原因。"
    "同一工具连续调用超过2次仍无结果时, 立即停止。"
    "一轮对话最多5次工具调用, 超出必须总结现状。"
)

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
        "model": "redteam", "choices": [{"index": 0, "message": {"role": "assistant", "content": f"[异常] {err}"}, "finish_reason": "stop"}]})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8894)), log_level="warning")

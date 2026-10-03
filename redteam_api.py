#!/usr/bin/env python3
"""红队工具引擎 API — 完整版 (Railway适配)"""
import json, os, time, sqlite3, hashlib, hmac, subprocess, re as _re, asyncio
from pathlib import Path
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from dotenv import load_dotenv

BASE = Path(__file__).parent
load_dotenv(BASE / ".env", override=True)

DEEPSEEK_API = os.getenv("DEEPSEEK_API", "https://api.deepseek.com/v1")
DEEPSEEK_KEY = os.getenv("DEEPSEEK_API_KEY", "")
MODEL_UP = "deepseek-chat"
DB = str(BASE / "data.db")
KEYS_F = BASE / "assistant_api_keys.json"
_ADMINS = {None, None}

app = FastAPI(title="whale-api")

sys_path_done = False
def _syspath():
    global sys_path_done
    if not sys_path_done:
        import sys
        sys.path.insert(0, str(BASE))
        sys.path.insert(0, str(BASE / "deepseek_bot"))
        sys_path_done = True

TOOLS_WHALE = [
 {"type":"function","function":{"name":"sh","description":"Run shell command","parameters":{"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"]}}},
 {"type":"function","function":{"name":"read","description":"Read file","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}},
 {"type":"function","function":{"name":"write","description":"Write file","parameters":{"type":"object","properties":{"path":{"type":"string"},"text":{"type":"string"}},"required":["path","text"]}}},
 {"type":"function","function":{"name":"edit","description":"Replace text in file","parameters":{"type":"object","properties":{"path":{"type":"string"},"old":{"type":"string"},"new":{"type":"string"}},"required":["path","old","new"]}}},
 {"type":"function","function":{"name":"search","description":"Web search (Google)","parameters":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}}},
 {"type":"function","function":{"name":"sys","description":"System:info/docker/svc/git/install","parameters":{"type":"object","properties":{"act":{"type":"string"},"tgt":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"url","description":"Fetch/extract/download/post webpage.","parameters":{"type":"object","properties":{"url":{"type":"string"},"act":{"type":"string"},"cookie":{"type":"string"},"data":{"type":"string"},"name":{"type":"string"}},"required":["url"]}}},
 {"type":"function","function":{"name":"file","description":"文件收发","parameters":{"type":"object","properties":{"name":{"type":"string"},"text":{"type":"string"},"act":{"type":"string"},"path":{"type":"string"}},"required":["name"]}}},
 {"type":"function","function":{"name":"coin","description":"Crypto price","parameters":{"type":"object","properties":{"coin":{"type":"string"}},"required":["coin"]}}},
 {"type":"function","function":{"name":"fofa","description":"FOFA资产测绘","parameters":{"type":"object","properties":{"act":{"type":"string"},"q":{"type":"string"},"limit":{"type":"integer"}},"required":["q"]}}},
 {"type":"function","function":{"name":"waf","description":"WAF逃逸","parameters":{"type":"object","properties":{"act":{"type":"string"},"attack_type":{"type":"string"},"payload":{"type":"string"},"target":{"type":"string"},"url_param":{"type":"string"},"waf_type":{"type":"string"}},"required":["payload"]}}},
 {"type":"function","function":{"name":"parse","description":"解析渗透工具输出","parameters":{"type":"object","properties":{"tool":{"type":"string"},"text":{"type":"string"},"project_id":{"type":"integer"}},"required":["tool","text"]}}},
 {"type":"function","function":{"name":"report","description":"生成渗透报告","parameters":{"type":"object","properties":{"act":{"type":"string"},"project_id":{"type":"integer"},"format":{"type":"string"}},"required":["act","project_id"]}}},
 {"type":"function","function":{"name":"data","description":"Bot data","parameters":{"type":"object","properties":{"act":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"memory","description":"长期记忆","parameters":{"type":"object","properties":{"act":{"type":"string"},"key":{"type":"string"},"value":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"img","description":"Image OCR","parameters":{"type":"object","properties":{"act":{"type":"string"},"path":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"shot","description":"Screenshot URL","parameters":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}},
 {"type":"function","function":{"name":"pdf","description":"Create/read PDF","parameters":{"type":"object","properties":{"act":{"type":"string"},"path":{"type":"string"},"text":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"captcha","description":"验证码识别","parameters":{"type":"object","properties":{"act":{"type":"string"},"url":{"type":"string"},"sitekey":{"type":"string"},"path":{"type":"string"},"module":{"type":"string"},"subdomain":{"type":"string"},"invisible":{"type":"boolean"},"min_score":{"type":"number"}},"required":["act"]}}},
 {"type":"function","function":{"name":"lateral","description":"横向移动","parameters":{"type":"object","properties":{"act":{"type":"string"},"target":{"type":"string"},"credential":{"type":"string"},"cmd":{"type":"string"},"domain":{"type":"string"},"username":{"type":"string"},"password":{"type":"string"},"chain":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"privesc","description":"提权","parameters":{"type":"object","properties":{"act":{"type":"string"},"target":{"type":"string"},"os":{"type":"string"},"method":{"type":"string"},"payload":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"credential","description":"凭证攻击","parameters":{"type":"object","properties":{"act":{"type":"string"},"target":{"type":"string"},"domain":{"type":"string"},"dc_ip":{"type":"string"},"username":{"type":"string"},"password":{"type":"string"},"hash":{"type":"string"},"hashes":{"type":"string"},"users":{"type":"string"},"krbtgt_hash":{"type":"string"},"service_hash":{"type":"string"},"service":{"type":"string"},"ticket":{"type":"string"},"interface":{"type":"string"},"analyze":{"type":"boolean"},"timeout":{"type":"integer"},"nt_hash":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"adaptive_chain","description":"自适应攻击链","parameters":{"type":"object","properties":{"act":{"type":"string"},"target":{"type":"string"},"project_id":{"type":"integer"},"chain_id":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"api_attack","description":"API攻击","parameters":{"type":"object","properties":{"act":{"type":"string"},"url":{"type":"string"},"token":{"type":"string"},"mode":{"type":"string"},"flow":{"type":"string"},"wordlist":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"c2","description":"C2集成","parameters":{"type":"object","properties":{"act":{"type":"string"},"protocol":{"type":"string"},"host":{"type":"string"},"port":{"type":"string"},"os":{"type":"string"},"arch":{"type":"string"},"target":{"type":"string"},"beacon_id":{"type":"string"},"method":{"type":"string"},"command":{"type":"string"},"profile":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"cloud","description":"云攻击","parameters":{"type":"object","properties":{"act":{"type":"string"},"target":{"type":"string"},"bucket":{"type":"string"},"vault":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"container","description":"容器逃逸","parameters":{"type":"object","properties":{"act":{"type":"string"},"technique":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"evasion","description":"规避引擎","parameters":{"type":"object","properties":{"act":{"type":"string"},"target":{"type":"string"},"payload_type":{"type":"string"},"lhost":{"type":"string"},"lport":{"type":"integer"},"level":{"type":"string"},"shellcode":{"type":"string"},"method":{"type":"string"},"technique":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"exfil","description":"数据外传","parameters":{"type":"object","properties":{"act":{"type":"string"},"target":{"type":"string"},"paths":{"type":"string"},"files":{"type":"string"},"output":{"type":"string"},"method":{"type":"string"},"password":{"type":"string"},"input":{"type":"string"},"chunk_size_mb":{"type":"integer"},"channel":{"type":"string"},"server_url":{"type":"string"},"domain":{"type":"string"},"target_ip":{"type":"string"},"encrypt":{"type":"string"},"split":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"strix","description":"Strix AI渗透测试","parameters":{"type":"object","properties":{"act":{"type":"string"},"target":{"type":"string"},"mode":{"type":"string"},"timeout":{"type":"integer"},"extra_args":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"get_current_time","description":"获取当前时间","parameters":{"type":"object","properties":{"tz":{"type":"string"}},"required":["tz"]}}},
 {"type":"function","function":{"name":"project","description":"项目记录管理","parameters":{"type":"object","properties":{"act":{"type":"string"},"name":{"type":"string"},"target":{"type":"string"},"id":{"type":"integer"}},"required":["act"]}}},
 {"type":"function","function":{"name":"team","description":"多AI协作","parameters":{"type":"object","properties":{"act":{"type":"string"},"task":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"schedule","description":"定时任务","parameters":{"type":"object","properties":{"act":{"type":"string"},"name":{"type":"string"},"cron":{"type":"string"},"action":{"type":"string"},"id":{"type":"integer"}},"required":["act"]}}},
 {"type":"function","function":{"name":"conversation_search","description":"对话搜索","parameters":{"type":"object","properties":{"q":{"type":"string"},"limit":{"type":"integer"}},"required":["q"]}}},
 {"type":"function","function":{"name":"proxy","description":"代理池管理","parameters":{"type":"object","properties":{"act":{"type":"string"},"value":{"type":"string"}},"required":["act"]}}},
 {"type":"function","function":{"name":"http_burst","description":"并发HTTP请求: url method data headers(JSON) n并发数","parameters":{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string"},"data":{"type":"string"},"headers":{"type":"string"},"n":{"type":"integer"}},"required":["url"]}}},
 {"type":"function","function":{"name":"jwt_decode","description":"解析JWT(不验签)","parameters":{"type":"object","properties":{"token":{"type":"string"}},"required":["token"]}}},
 {"type":"function","function":{"name":"jwt_forge","description":"伪造JWT: payload(JSON) secret(留空试none) alg","parameters":{"type":"object","properties":{"payload":{"type":"string"},"secret":{"type":"string"},"alg":{"type":"string"}},"required":["payload"]}}},
]

_CG_IDS = {"btc":"bitcoin","eth":"ethereum","usdt":"tether","trx":"tron","ton":"the-open-network","doge":"dogecoin","sol":"solana","bnb":"binancecoin","xrp":"ripple","ltc":"litecoin","shib":"shiba-inu","pepe":"pepe","sui":"sui","usdc":"usd-coin","pol":"matic-network","matic":"matic-network","bch":"bitcoin-cash","ada":"cardano","dai":"dai","uni":"uniswap","atom":"cosmos","near":"near","avax":"avalanche-2","apt":"aptos","okb":"okb","gmt":"stepn","fil":"filecoin","dot":"polkadot","link":"chainlink","dog":"dogecoin","mew":"mew","bonk":"bonk","arb":"arbitrum","op":"optimism","mkr":"maker"}

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


SUBAGENT_SYS = "你是红队专职执行子agent。独立上下文, 只干被分配的活, 干完用三句话总结。"


def _subagent_sync(task, uid, rounds=6):
    _sm = [{"role": "system", "content": SUBAGENT_SYS}, {"role": "user", "content": task}]
    try:
        for _ri in range(rounds):
            r = httpx.post(f"{DEEPSEEK_API}/chat/completions",
                           headers={"Authorization": f"Bearer {DEEPSEEK_KEY}", "Content-Type": "application/json"},
                           json={"model": MODEL_UP, "messages": _sm, "tools": TOOLS_WHALE, "max_tokens": 4096, "stream": False}, timeout=150)
            if r.status_code != 200:
                return f"子任务失败(HTTP {r.status_code})"
            _msg = r.json()["choices"][0]["message"]
            if not _msg.get("tool_calls"):
                _sm.append({"role": "assistant", "content": _msg.get("content") or ""})
                return (_msg.get("content") or "").strip() or "子任务完成(无输出)"
            _sm.append({"role": "assistant", "content": _msg.get("content") or "", "tool_calls": _msg["tool_calls"]})
            for _tc in _msg["tool_calls"]:
                if not isinstance(_tc, dict): continue
                try: _args = json.loads(_tc["function"].get("arguments", "{}") or "{}")
                except Exception: _args = {}
                if not isinstance(_args, dict): _args = {}
                _res = _exec_tool(_tc["function"]["name"], _args, uid)
                _sm.append({"role": "tool", "tool_call_id": _tc.get("id", "") or f"call_{time.time():.0f}", "content": _res[:8000]})
        return "子任务轮次耗尽, 未完成"
    except Exception as _e:
        return f"子任务异常: {_e}"


# ===== 第一段结束，第二段从这里继续 =====

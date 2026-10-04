#!/usr/bin/env python3
"""Telegram Bot 控制器 - 调用 redteam_api.py 的红队工具"""
import os
import json
import asyncio
from pathlib import Path
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, filters
from dotenv import load_dotenv

# 导入我们改好的红队主程序
import sys
sys.path.insert(0, str(Path(__file__).parent))
from redteam_api import _agent_loop, TOOLS_WHALE, SYSTEM_PROMPT

BASE = Path(__file__).parent
load_dotenv(BASE / ".env", override=True)

BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
# 白名单：只有这些 TG 用户 ID 才能使用！
ALLOWED_UIDS = {8229799375,7817182719,7766754548}  # 改成你自己的 TG 数字ID，多个用逗号隔开

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text or ""
    
    # 安全校验：白名单过滤
    if user_id not in ALLOWED_UIDS:
        await update.message.reply_text("⛔ 未授权用户，拒绝访问。")
        return
    
    if not text:
        await update.message.reply_text("请输入指令（例如：扫描 192.168.56.101 并告诉我开了什么端口）")
        return

    await update.message.reply_text("⏳ 正在执行，请稍候...")

    # 组装消息发给红队引擎
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": text}
    ]
    
    try:
        # 放到线程里跑，避免阻塞 Telegram Bot 的事件循环
        cur, err, final_msg = await asyncio.to_thread(_agent_loop, user_id, messages)
        
        if final_msg is not None:
            result = final_msg.get("content") or "[执行完成，无文本输出]"
        else:
            result = f"[循环终止] {err}"
            
        # Telegram 消息长度限制，超长自动切分
        max_len = 4000
        for i in range(0, len(result), max_len):
            await update.message.reply_text(result[i:i+max_len])
            
    except Exception as e:
        await update.message.reply_text(f"❌ 执行异常: {type(e).__name__}: {str(e)[:300]}")

if __name__ == "__main__":
    if not BOT_TOKEN:
        print("❌ 请在 .env 中配置 TG_BOT_TOKEN")
        sys.exit(1)
        
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("🤖 Telegram Bot 已启动，等待指令...")
    app.run_polling()

"""
telegram_io.py — Bidirectional Telegram I/O for Clicker.
Sends questions to Telegram and waits for replies in parallel with local stdin.
First reply wins. Falls back to default on timeout.
"""
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request
from queue import Queue, Empty

_RST = "\033[0m"
_DIM = "\033[2m"
_G   = "\033[92m"
_Y   = "\033[93m"
_R   = "\033[91m"

_token = ""
_chat_id = ""
_last_update_id = 0
_lock = threading.Lock()


def flush_pending(max_rounds=5):
    """Drain any stale Telegram messages so they don't win the next ask().
    Returns the number of drained updates."""
    if not is_enabled():
        return 0
    global _last_update_id
    total = 0
    for _ in range(max_rounds):
        updates = _get_updates(_last_update_id + 1, long_poll=1)
        if not updates:
            break
        for u in updates:
            uid = u.get("update_id", 0)
            if uid > _last_update_id:
                _last_update_id = uid
            total += 1
    return total


def configure(token, chat_id):
    """Set bot token + chat_id. Safe to call multiple times.
    Also flushes stale updates so the next ask() ignores old messages."""
    global _token, _chat_id
    _token = str(token or "").strip()
    _chat_id = str(chat_id or "").strip()
    # Drain anything pending before we start
    if _token and _chat_id:
        try:
            flush_pending()
        except Exception:
            pass


def is_enabled():
    return bool(_token and _chat_id)


def _api(method, params=None, timeout=15):
    if not _token:
        return None
    url = f"https://api.telegram.org/bot{_token}/{method}"
    data = urllib.parse.urlencode(params or {}).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception:
        return None


def send_question(text, buttons=None):
    """Send a message. buttons=[[("Yes","yes"),("No","no")]] for inline keyboard."""
    if not is_enabled():
        return False
    params = {
        "chat_id": _chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }
    if buttons:
        kb = {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in buttons]}
        params["reply_markup"] = json.dumps(kb)
    r = _api("sendMessage", params)
    return bool(r and r.get("ok"))


def _get_updates(offset, long_poll=25):
    if not _token:
        return []
    url = f"https://api.telegram.org/bot{_token}/getUpdates"
    params = {
        "offset": offset,
        "timeout": long_poll,
        "allowed_updates": json.dumps(["message", "callback_query"]),
    }
    data = urllib.parse.urlencode(params).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=long_poll + 10) as res:
            r = json.loads(res.read().decode("utf-8"))
            if r.get("ok"):
                return r.get("result", [])
    except Exception:
        pass
    return []


def _answer_cb(cb_id, text=""):
    _api("answerCallbackQuery", {"callback_query_id": cb_id, "text": text}, timeout=5)


def _extract(update):
    """Return (value_or_None, update_id). Filters by chat_id."""
    uid = update.get("update_id", 0)
    cb = update.get("callback_query")
    if cb:
        chat = str((cb.get("message") or {}).get("chat", {}).get("id", ""))
        if chat != _chat_id:
            return None, uid
        _answer_cb(cb.get("id", ""), "received")
        return cb.get("data", ""), uid
    msg = update.get("message")
    if msg:
        chat = str(msg.get("chat", {}).get("id", ""))
        if chat != _chat_id:
            return None, uid
        return (msg.get("text") or "").strip(), uid
    return None, uid


def flush_now():
    """Immediately drain all pending Telegram updates (no wait)."""
    if not is_enabled():
        return 0
    global _last_update_id
    total = 0
    # Get the latest update_id without long-polling
    for _ in range(2):
        updates = _get_updates(_last_update_id + 1, long_poll=0)
        if not updates:
            break
        for u in updates:
            uid = u.get("update_id", 0)
            if uid > _last_update_id:
                _last_update_id = uid
            total += 1
    return total


def ask(prompt, kind="yesno", default="n", local_timeout=10, tg_timeout=60):
    """
    Ask via local stdin AND Telegram in parallel. First reply wins.
    kind="yesno" -> returns "y" or "n"
    kind="text"  -> returns the raw text
    """
    # CRITICAL: flush stale messages BEFORE sending a new question.
    # Otherwise an old callback/message could win over the user's fresh answer.
    try:
        flush_now()
    except Exception:
        pass

    tty = sys.stdin.isatty()
    tg = is_enabled()

    if not tty and not tg:
        return default

    if tg:
        if kind == "yesno":
            buttons = [[("\u2705 Yes", "yes"), ("\u274c No", "no")]]
            send_question(f"\u2753 <b>{prompt}</b>\n<i>Reply via buttons or type y/n.</i>", buttons=buttons)
        else:
            send_question(f"\U0001f4dd <b>{prompt}</b>\n<i>Reply with text.</i>", buttons=None)
        # Small delay to let Telegram register our send before we start reading
        import time as _t
        _t.sleep(0.3)
        try:
            flush_now()
        except Exception:
            pass

    result_q = Queue()

    if tty:
        def _local():
            try:
                sys.stdout.write(f"{prompt} ")
                sys.stdout.flush()
                import select as _sel
                r, _, _ = _sel.select([sys.stdin], [], [], local_timeout)
                if r:
                    ans = sys.stdin.readline().strip()
                    if ans:
                        result_q.put(("local", ans))
            except Exception:
                pass
        threading.Thread(target=_local, daemon=True).start()

    if tg:
        def _tg():
            global _last_update_id
            deadline = time.time() + tg_timeout
            while time.time() < deadline:
                with _lock:
                    offset = _last_update_id + 1
                remain = int(deadline - time.time()) + 1
                updates = _get_updates(offset, long_poll=min(25, remain))
                for u in updates:
                    val, uid = _extract(u)
                    with _lock:
                        if uid > _last_update_id:
                            _last_update_id = uid
                    if val is None:
                        continue
                    result_q.put(("tg", val))
                    return
                time.sleep(0.3)
        threading.Thread(target=_tg, daemon=True).start()

    try:
        src, val = result_q.get(timeout=tg_timeout + 5)
    except Empty:
        return default

    if kind == "yesno":
        v = str(val).lower().strip()
        if v in ("y", "yes", "\u2705 yes"):
            return "y"
        if v in ("n", "no", "", "\u274c no"):
            return "n"
        return default
    return str(val) if val else default


def notify(text):
    """Fire-and-forget notification."""
    if is_enabled():
        send_question(text)

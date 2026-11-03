"""Persistent MLX generation process. One JSON object per stdin line, one per stdout line."""

import json
import sys

_out = sys.stdout
sys.stdout = sys.stderr


def emit(payload: dict) -> None:
    _out.write(json.dumps(payload, ensure_ascii=False) + "\n")
    _out.flush()


try:
    from mlx_lm import load
    from mlx_lm.generate import generate
except Exception as exc:
    emit({"ok": False, "error": f"mlx-lm is not installed for this Python ({exc})"})
    raise SystemExit(1)

model = None
tokenizer = None
loaded = None


def chat_prompt(system: str, user: str) -> str:
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    apply = getattr(tokenizer, "apply_chat_template", None)
    if apply is not None:
        try:
            rendered = apply(messages, add_generation_prompt=True, tokenize=False)
            if isinstance(rendered, str):
                return rendered
        except Exception:
            pass
    return f"{system}\n\n{user}"


for raw in sys.stdin:
    line = raw.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
        op = req.get("op")
        if op == "load":
            path = str(req.get("path") or "")
            if not path:
                emit({"ok": False, "error": "missing model path"})
                continue
            if loaded != path:
                model, tokenizer = load(path)
                loaded = path
            emit({"ok": True})
        elif op == "prompt":
            if model is None or tokenizer is None:
                emit({"ok": False, "error": "MLX model is not loaded"})
                continue
            text = generate(
                model,
                tokenizer,
                prompt=chat_prompt(str(req.get("system") or ""), str(req.get("prompt") or "")),
                max_tokens=int(req.get("max_tokens") or 256),
                verbose=False,
            )
            emit({"ok": True, "text": text or ""})
        else:
            emit({"ok": False, "error": "unknown op"})
    except Exception as exc:
        emit({"ok": False, "error": str(exc)})

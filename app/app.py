"""
Echo-приложение для тестового стенда.

Назначение: вывести то, что приложение реально получает по HTTP - в первую очередь
заголовок X-Forwarded-For и адрес ближайшего соседа ($remote_addr с точки зрения app).
Никакой бизнес-логики; задача - быть детерминированной точкой наблюдения.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="XFF Echo", version="1.0.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def echo(request: Request, path: str) -> JSONResponse:
    xff_raw = request.headers.get("x-forwarded-for")
    xff_chain = [item.strip() for item in xff_raw.split(",")] if xff_raw else []

    payload = {
        "path": f"/{path}",
        "method": request.method,
        "immediate_peer": request.client.host if request.client else None,
        "x_forwarded_for_raw": xff_raw,
        "x_forwarded_for_chain": xff_chain,
        "x_forwarded_for_hops": len(xff_chain),
        "headers": {k.lower(): v for k, v in request.headers.items()},
    }
    return JSONResponse(payload)

import os
import re
import secrets
import sys
from datetime import datetime, timezone
from typing import Final

import redis
import uvicorn
from fastapi import Cookie, FastAPI, Response, status
from fastapi.responses import JSONResponse

app = FastAPI()

COOKIE_NAME: Final = "X-Session-Id"
SID_PATTERN: Final = re.compile(r"^[0-9a-f]{32}$")

def get_env_variable(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        print(f"ERROR: {name} is not set", file=sys.stderr)
        sys.exit(1)
    return value

APP_HOST = get_env_variable("APP_HOST")
APP_PORT = int(get_env_variable("APP_PORT"))
APP_USER_SESSION_TTL = int(get_env_variable("APP_USER_SESSION_TTL"))
REDIS_HOST = get_env_variable("REDIS_HOST")
REDIS_PORT = int(get_env_variable("REDIS_PORT"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_DB = int(get_env_variable("REDIS_DB"))

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD or None,
    db=REDIS_DB,
    decode_responses=True,
)

CREATE_SESSION_SCRIPT = redis_client.register_script(
    """
    if redis.call('EXISTS', KEYS[1]) == 1 then
        return 0
    end
    redis.call('HSET', KEYS[1], 'created_at', ARGV[1], 'updated_at', ARGV[1])
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
    return 1
    """
)

def now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def generate_sid() -> str:
    return secrets.token_hex(16)

def is_valid_sid(sid: str | None) -> bool:
    return bool(sid and SID_PATTERN.fullmatch(sid))

def session_key(sid: str) -> str:
    return f"sid:{sid}"

def set_session_cookie(response: Response, sid: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=sid,
        httponly=True,
        max_age=APP_USER_SESSION_TTL,
        path="/",
    )

def create_session() -> str:
    timestamp = now_rfc3339()

    for _ in range(5):
        sid = generate_sid()
        created = CREATE_SESSION_SCRIPT(
            keys=[session_key(sid)],
            args=[timestamp, str(APP_USER_SESSION_TTL)],
        )
        if int(created) == 1:
            return sid

    raise RuntimeError("failed create a session id")

def refresh_session(sid: str) -> bool:
    key = session_key(sid)
    if redis_client.exists(key) != 1:
        return False

    pipeline = redis_client.pipeline(transaction=True)
    pipeline.hset(key, mapping={"updated_at": now_rfc3339()})
    pipeline.expire(key, APP_USER_SESSION_TTL)
    pipeline.execute()
    return True


@app.get("/health")
def healthcheck(x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> JSONResponse:
    response = JSONResponse(content={"status": "ok"})

    if is_valid_sid(x_session_id):
        set_session_cookie(response, x_session_id)

    return response


@app.post("/session", status_code=status.HTTP_201_CREATED)
def upsert_session(
    response: Response,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> Response:
    if is_valid_sid(x_session_id) and refresh_session(x_session_id):
        response = Response(content="", status_code=status.HTTP_200_OK)
        set_session_cookie(response, x_session_id)
        return response

    sid = create_session()
    response = Response(content="", status_code=status.HTTP_201_CREATED)
    set_session_cookie(response, sid)
    return response

if __name__ == "__main__":
    host = get_env_variable("APP_HOST")
    port = int(get_env_variable("APP_PORT"))

    uvicorn.run(app, host=host, port=port)
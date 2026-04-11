import os
import re
import secrets
import sys
from datetime import datetime, timezone
from typing import Any, Final

import bcrypt
import redis
import uvicorn
from bson import ObjectId
from fastapi import Cookie, FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from pymongo import ASCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError


app = FastAPI()

COOKIE_NAME: Final = "X-Session-Id"
SID_PATTERN: Final = re.compile(r"^[0-9a-f]{32}$")


def get_env_variable(name: str) -> str:
    value = os.getenv(name)
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
MONGODB_DATABASE = get_env_variable("MONGODB_DATABASE")
MONGODB_USER = get_env_variable("MONGODB_USER")
MONGODB_PASSWORD = get_env_variable("MONGODB_PASSWORD")
MONGODB_HOST = get_env_variable("MONGODB_HOST")
MONGODB_PORT = int(get_env_variable("MONGODB_PORT"))

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD or None,
    db=REDIS_DB,
    decode_responses=True,
)

mongo_uri = (
    f"mongodb://{MONGODB_USER}:{MONGODB_PASSWORD}"
    f"@{MONGODB_HOST}:{MONGODB_PORT}/{MONGODB_DATABASE}"
)
mongo_client = MongoClient(mongo_uri)

database = mongo_client[MONGODB_DATABASE]
users_collection: Collection = database["users"]
events_collection: Collection = database["events"]

users_collection.create_index([("username", ASCENDING)], unique=True, name="username_unique")
events_collection.create_index([("title", ASCENDING)], unique=True, name="title_unique")
events_collection.create_index([("title", ASCENDING), ("created_by", ASCENDING)], name="title_created_by")
events_collection.create_index([("created_by", ASCENDING)], name="created_by")

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

def delete_session_cookie(response: Response, sid: str = "") -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=sid,
        httponly=True,
        max_age=0,
        path="/",
    )

def create_session(user_id: str | None = None) -> str:
    timestamp = now_rfc3339()

    for _ in range(5):
        sid = generate_sid()
        created = CREATE_SESSION_SCRIPT(
            keys=[session_key(sid)],
            args=[timestamp, str(APP_USER_SESSION_TTL)],
        )
        if int(created) == 1:
            if user_id is not None:
                redis_client.hset(session_key(sid), mapping={"user_id": user_id})
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

def get_session_data(sid: str | None) -> dict[str, str] | None:
    if not is_valid_sid(sid):
        return None

    key = session_key(sid)
    if redis_client.exists(key) != 1:
        return None

    data = redis_client.hgetall(key)
    if not data:
        return None

    return data

def bind_session_to_user(sid: str, user_id: str) -> None:
    key = session_key(sid)
    pipeline = redis_client.pipeline(transaction=True)
    pipeline.hset(key, mapping={"user_id": user_id, "updated_at": now_rfc3339()})
    pipeline.expire(key, APP_USER_SESSION_TTL)
    pipeline.execute()

def delete_session(sid: str | None) -> None:
    if is_valid_sid(sid):
        redis_client.delete(session_key(sid))

def maybe_refresh_post_session(sid: str | None) -> str | None:
    if is_valid_sid(sid) and refresh_session(sid):
        return sid
    return None

def maybe_attach_existing_session_cookie(response: Response, sid: str | None) -> None:
    if is_valid_sid(sid) and redis_client.exists(session_key(sid)) == 1:
        set_session_cookie(response, sid)

def json_error(message: str, status_code: int, sid: str | None = None, refresh: bool = False) -> JSONResponse:
    response = JSONResponse(content={"message": message}, status_code=status_code)
    if refresh:
        sid = maybe_refresh_post_session(sid)
    maybe_attach_existing_session_cookie(response, sid)
    return response

def empty_response(status_code: int, sid: str | None = None) -> Response:
    response = Response(content=b"", status_code=status_code)
    if sid is not None:
        set_session_cookie(response, sid)
    return response

def parse_json_body(body: bytes) -> dict[str, Any] | None:
    if not body:
        return None
    try:
        import json

        data = json.loads(body)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data

def get_non_empty_string(data: dict[str, Any], field_name: str) -> str | None:
    value = data.get(field_name)
    if not isinstance(value, str):
        return None
    if value == "":
        return None
    return value

def is_valid_rfc3339(value: str) -> bool:
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return parsed.tzinfo is not None

@app.get("/health")
def healthcheck(x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> JSONResponse:
    response = JSONResponse(content={"status": "ok"})
    maybe_attach_existing_session_cookie(response, x_session_id)
    return response

@app.post("/session")
def upsert_session(x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> Response:
    if is_valid_sid(x_session_id) and refresh_session(x_session_id):
        return empty_response(status.HTTP_200_OK, x_session_id)

    sid = create_session()
    return empty_response(status.HTTP_201_CREATED, sid)

@app.post("/users")
async def create_user(
    request: Request,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> Response:
    body = parse_json_body(await request.body())
    if body is None:
        return json_error('invalid "full_name" field', status.HTTP_400_BAD_REQUEST, x_session_id, refresh=True)

    full_name = get_non_empty_string(body, "full_name")
    if full_name is None:
        return json_error('invalid "full_name" field', status.HTTP_400_BAD_REQUEST, x_session_id, refresh=True)

    username = get_non_empty_string(body, "username")
    if username is None:
        return json_error('invalid "username" field', status.HTTP_400_BAD_REQUEST, x_session_id, refresh=True)

    password = get_non_empty_string(body, "password")
    if password is None:
        return json_error('invalid "password" field', status.HTTP_400_BAD_REQUEST, x_session_id, refresh=True)

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        result = users_collection.insert_one(
            {
                "full_name": full_name,
                "username": username,
                "password_hash": password_hash,
            }
        )
    except DuplicateKeyError:
        return json_error("user already exists", status.HTTP_409_CONFLICT, x_session_id, refresh=True)

    sid = create_session(user_id=str(result.inserted_id))
    return empty_response(status.HTTP_201_CREATED, sid)


@app.post("/auth/login")
async def login(
    request: Request,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> Response:
    body = parse_json_body(await request.body())
    if body is None:
        return json_error("invalid credentials", status.HTTP_401_UNAUTHORIZED, x_session_id, refresh=True)

    username = get_non_empty_string(body, "username")
    password = get_non_empty_string(body, "password")
    if username is None or password is None:
        return json_error("invalid credentials", status.HTTP_401_UNAUTHORIZED, x_session_id, refresh=True)

    user = users_collection.find_one({"username": username})
    if user is None:
        return json_error("invalid credentials", status.HTTP_401_UNAUTHORIZED, x_session_id, refresh=True)

    password_hash = user.get("password_hash")
    if not isinstance(password_hash, str) or not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
        return json_error("invalid credentials", status.HTTP_401_UNAUTHORIZED, x_session_id, refresh=True)

    sid = maybe_refresh_post_session(x_session_id)
    if sid is None:
        sid = create_session(user_id=str(user["_id"]))
    else:
        bind_session_to_user(sid, str(user["_id"]))

    return empty_response(status.HTTP_204_NO_CONTENT, sid)


@app.post("/auth/logout")
def logout(x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> Response:
    delete_session(x_session_id)
    response = Response(content=b"", status_code=status.HTTP_204_NO_CONTENT)
    delete_session_cookie(response, x_session_id or "")
    return response

@app.post("/events")
async def create_event(
    request: Request,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> Response:
    sid = maybe_refresh_post_session(x_session_id)
    session_data = get_session_data(sid)
    user_id = session_data.get("user_id") if session_data else None
    if sid is None or not user_id:
        return empty_response(status.HTTP_401_UNAUTHORIZED, sid)

    body = parse_json_body(await request.body())
    if body is None:
        return json_error('invalid "title" field', status.HTTP_400_BAD_REQUEST, sid)

    title = get_non_empty_string(body, "title")
    if title is None:
        return json_error('invalid "title" field', status.HTTP_400_BAD_REQUEST, sid)

    address = get_non_empty_string(body, "address")
    if address is None:
        return json_error('invalid "address" field', status.HTTP_400_BAD_REQUEST, sid)

    started_at = get_non_empty_string(body, "started_at")
    if started_at is None or not is_valid_rfc3339(started_at):
        return json_error('invalid "started_at" field', status.HTTP_400_BAD_REQUEST, sid)

    finished_at = get_non_empty_string(body, "finished_at")
    if finished_at is None or not is_valid_rfc3339(finished_at):
        return json_error('invalid "finished_at" field', status.HTTP_400_BAD_REQUEST, sid)

    description = body.get("description", "")
    if description is None:
        description = ""
    if not isinstance(description, str):
        return json_error('invalid "description" field', status.HTTP_400_BAD_REQUEST, sid)

    event_document = {
        "title": title,
        "description": description,
        "location": {"address": address},
        "created_at": now_rfc3339(),
        "created_by": user_id,
        "started_at": started_at,
        "finished_at": finished_at,
    }

    try:
        result = events_collection.insert_one(event_document)
    except DuplicateKeyError:
        return json_error("event already exists", status.HTTP_409_CONFLICT, sid)

    response = JSONResponse(content={"id": str(result.inserted_id)}, status_code=status.HTTP_201_CREATED)
    set_session_cookie(response, sid)
    return response

@app.get("/events")
def get_events(
    title: str | None = None,
    limit: str | None = None,
    offset: str | None = None,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> JSONResponse:
    if limit is not None:
        try:
            limit_value = int(limit)
        except ValueError:
            return json_error('invalid "limit" parameter', status.HTTP_400_BAD_REQUEST, x_session_id)
        if limit_value < 0:
            return json_error('invalid "limit" parameter', status.HTTP_400_BAD_REQUEST, x_session_id)
    else:
        limit_value = 0

    if offset is not None:
        try:
            offset_value = int(offset)
        except ValueError:
            return json_error('invalid "offset" parameter', status.HTTP_400_BAD_REQUEST, x_session_id)
        if offset_value < 0:
            return json_error('invalid "offset" parameter', status.HTTP_400_BAD_REQUEST, x_session_id)
    else:
        offset_value = 0

    query: dict[str, Any] = {}
    if title is not None:
        query["title"] = {"$regex": re.escape(title), "$options": "i"}

    cursor = events_collection.find(query).sort("_id", ASCENDING).skip(offset_value)
    if limit_value > 0:
        cursor = cursor.limit(limit_value)

    events = []
    for document in cursor:
        events.append(
            {
                "id": str(document["_id"]),
                "title": document.get("title", ""),
                "description": document.get("description", ""),
                "location": document.get("location", {"address": ""}),
                "created_at": document.get("created_at", ""),
                "created_by": document.get("created_by", ""),
                "started_at": document.get("started_at", ""),
                "finished_at": document.get("finished_at", ""),
            }
        )

    response = JSONResponse(content={"events": events, "count": len(events)}, status_code=status.HTTP_200_OK)
    maybe_attach_existing_session_cookie(response, x_session_id)
    return response


if __name__ == "__main__":
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)

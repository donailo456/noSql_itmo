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
VALID_CATEGORIES: Final = {"meetup", "concert", "exhibition", "party", "other"}


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
    f"mongodb://{MONGODB_HOST}:{MONGODB_PORT}/{MONGODB_DATABASE}"
)
mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)

database = mongo_client[MONGODB_DATABASE]
users_collection: Collection = database["users"]
events_collection: Collection = database["events"]

import time as _time
for _attempt in range(30):
    try:
        users_collection.create_index([("username", ASCENDING)], unique=True, name="username_unique")
        events_collection.create_index([("created_by", ASCENDING)], name="created_by")
        break
    except Exception as e:
        print(f"Waiting for MongoDB to be ready... attempt {_attempt + 1}: {e}", file=sys.stderr)
        _time.sleep(5)

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

def format_event(document: dict[str, Any]) -> dict[str, Any]:
    """Format a MongoDB event document into the API response format."""
    result: dict[str, Any] = {
        "id": str(document["_id"]),
        "title": document.get("title", ""),
        "description": document.get("description", ""),
        "location": document.get("location", {"address": ""}),
        "created_at": document.get("created_at", ""),
        "created_by": document.get("created_by", ""),
        "started_at": document.get("started_at", ""),
        "finished_at": document.get("finished_at", ""),
    }
    if "category" in document:
        result["category"] = document["category"]
    if "price" in document:
        result["price"] = document["price"]
    return result

def format_user(document: dict[str, Any]) -> dict[str, Any]:
    """Format a MongoDB user document into the API response format (without password_hash)."""
    return {
        "id": str(document["_id"]),
        "full_name": document.get("full_name", ""),
        "username": document.get("username", ""),
    }

def parse_uint_param(value: str | None, field_name: str, sid: str | None = None) -> tuple[int | None, JSONResponse | None]:
    """Parse and validate an unsigned integer query parameter. Returns (value, error_response)."""
    if value is None:
        return None, None
    try:
        int_value = int(value)
    except ValueError:
        return None, json_error(f'invalid "{field_name}" field', status.HTTP_400_BAD_REQUEST, sid)
    if int_value < 0:
        return None, json_error(f'invalid "{field_name}" field', status.HTTP_400_BAD_REQUEST, sid)
    return int_value, None

def parse_yyyymmdd(value: str, field_name: str, sid: str | None = None) -> tuple[datetime | None, JSONResponse | None]:
    """Parse a YYYYMMDD date string. Returns (datetime, error_response)."""
    if not re.fullmatch(r"\d{8}", value):
        return None, json_error(f'invalid "{field_name}" field', status.HTTP_400_BAD_REQUEST, sid)
    try:
        return datetime.strptime(value, "%Y%m%d").replace(tzinfo=timezone.utc), None
    except ValueError:
        return None, json_error(f'invalid "{field_name}" field', status.HTTP_400_BAD_REQUEST, sid)

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
        return json_error('invalid "body" field', status.HTTP_400_BAD_REQUEST, x_session_id, refresh=True)

    username = get_non_empty_string(body, "username")
    if username is None:
        return json_error('invalid "username" field', status.HTTP_400_BAD_REQUEST, x_session_id, refresh=True)

    password = get_non_empty_string(body, "password")
    if password is None:
        return json_error('invalid "password" field', status.HTTP_400_BAD_REQUEST, x_session_id, refresh=True)

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
    if x_session_id is None or not refresh_session(x_session_id):
        return Response(content=b"", status_code=status.HTTP_401_UNAUTHORIZED)

    delete_session(x_session_id)
    response = Response(content=b"", status_code=status.HTTP_204_NO_CONTENT)
    delete_session_cookie(response, x_session_id)
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

    existing = events_collection.find_one({"title": title, "created_by": user_id})
    if existing is not None:
        return json_error("event already exists", status.HTTP_409_CONFLICT, sid)

    result = events_collection.insert_one(event_document)

    response = JSONResponse(content={"id": str(result.inserted_id)}, status_code=status.HTTP_201_CREATED)
    set_session_cookie(response, sid)
    return response

@app.get("/events", response_model=None)
def get_events(
    title: str | None = None,
    limit: str | None = None,
    offset: str | None = None,
    id: str | None = None,
    category: str | None = None,
    price_from: str | None = None,
    price_to: str | None = None,
    city: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    user: str | None = None,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
):
    limit_value, err = parse_uint_param(limit, "limit", x_session_id)
    if err is not None:
        return err

    offset_value, err = parse_uint_param(offset, "offset", x_session_id)
    if err is not None:
        return err

    query: dict[str, Any] = {}

    if id is not None:
        if not ObjectId.is_valid(id):
            return json_error('invalid "id" field', status.HTTP_400_BAD_REQUEST, x_session_id)
        query["_id"] = ObjectId(id)

    if title is not None:
        query["title"] = {"$regex": re.escape(title), "$options": "i"}

    if category is not None:
        if category not in VALID_CATEGORIES:
            return json_error('invalid "category" field', status.HTTP_400_BAD_REQUEST, x_session_id)
        query["category"] = category

    price_conditions: dict[str, Any] = {}
    if price_from is not None:
        pf_val, err = parse_uint_param(price_from, "price_from", x_session_id)
        if err is not None:
            return err
        if pf_val is not None:
            price_conditions["$gte"] = pf_val
    if price_to is not None:
        pt_val, err = parse_uint_param(price_to, "price_to", x_session_id)
        if err is not None:
            return err
        if pt_val is not None:
            price_conditions["$lte"] = pt_val
    if price_conditions:
        query["price"] = price_conditions

    if city is not None:
        query["location.city"] = city

    date_conditions: dict[str, Any] = {}
    if date_from is not None:
        dt_from, err = parse_yyyymmdd(date_from, "date_from", x_session_id)
        if err is not None:
            return err
        if dt_from is not None:
            date_conditions["$gte"] = dt_from.strftime("%Y-%m-%dT%H:%M:%S")
    if date_to is not None:
        dt_to, err = parse_yyyymmdd(date_to, "date_to", x_session_id)
        if err is not None:
            return err
        if dt_to is not None:
            date_conditions["$lte"] = dt_to.strftime("%Y-%m-%dT23:59:59")
    if date_conditions:
        query["started_at"] = date_conditions

    if user is not None:
        user_doc = users_collection.find_one({"username": user})
        if user_doc is None:
            response = JSONResponse(content={"events": [], "count": 0}, status_code=status.HTTP_200_OK)
            maybe_attach_existing_session_cookie(response, x_session_id)
            return response
        query["created_by"] = str(user_doc["_id"])

    cursor = events_collection.find(query).sort("_id", ASCENDING).skip(offset_value or 0)
    if limit_value and limit_value > 0:
        cursor = cursor.limit(limit_value)

    events = [format_event(doc) for doc in cursor]

    response = JSONResponse(content={"events": events, "count": len(events)}, status_code=status.HTTP_200_OK)
    maybe_attach_existing_session_cookie(response, x_session_id)
    return response


@app.get("/events/{event_id}", response_model=None)
def get_event(
    event_id: str,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
):
    if not ObjectId.is_valid(event_id):
        response = JSONResponse(content={"message": "Not found"}, status_code=status.HTTP_404_NOT_FOUND)
        maybe_attach_existing_session_cookie(response, x_session_id)
        return response

    document = events_collection.find_one({"_id": ObjectId(event_id)})
    if document is None:
        response = JSONResponse(content={"message": "Not found"}, status_code=status.HTTP_404_NOT_FOUND)
        maybe_attach_existing_session_cookie(response, x_session_id)
        return response

    result = format_event(document)
    response = JSONResponse(content=result, status_code=status.HTTP_200_OK)
    maybe_attach_existing_session_cookie(response, x_session_id)
    return response


@app.patch("/events/{event_id}")
async def patch_event(
    request: Request,
    event_id: str,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> Response:
    sid = maybe_refresh_post_session(x_session_id)
    session_data = get_session_data(sid)
    user_id = session_data.get("user_id") if session_data else None
    if sid is None or not user_id:
        return empty_response(status.HTTP_401_UNAUTHORIZED, sid)

    if not ObjectId.is_valid(event_id):
        return json_error("Not found. Be sure that event exists and you are the organizer", status.HTTP_404_NOT_FOUND, sid)

    event = events_collection.find_one({"_id": ObjectId(event_id)})
    if event is None:
        return json_error("Not found. Be sure that event exists and you are the organizer", status.HTTP_404_NOT_FOUND, sid)

    if event.get("created_by") != user_id:
        return json_error("Not found. Be sure that event exists and you are the organizer", status.HTTP_404_NOT_FOUND, sid)

    body = parse_json_body(await request.body())
    if body is None:
        return json_error('invalid "category" field', status.HTTP_400_BAD_REQUEST, sid)

    update_fields: dict[str, Any] = {}
    unset_fields: dict[str, Any] = {}

    if "category" in body:
        category = body["category"]
        if not isinstance(category, str) or category not in VALID_CATEGORIES:
            return json_error('invalid "category" field', status.HTTP_400_BAD_REQUEST, sid)
        update_fields["category"] = category

    if "price" in body:
        price = body["price"]
        if not isinstance(price, int) or price < 0:
            return json_error('invalid "price" field', status.HTTP_400_BAD_REQUEST, sid)
        update_fields["price"] = price

    if "city" in body:
        city = body["city"]
        if not isinstance(city, str):
            return json_error('invalid "city" field', status.HTTP_400_BAD_REQUEST, sid)
        if city == "":
            unset_fields["location.city"] = ""
        else:
            update_fields["location.city"] = city

    update_operation: dict[str, Any] = {}
    if update_fields:
        update_operation["$set"] = update_fields
    if unset_fields:
        update_operation["$unset"] = unset_fields

    if update_operation:
        events_collection.update_one({"_id": ObjectId(event_id)}, update_operation)

    return empty_response(status.HTTP_204_NO_CONTENT, sid)


@app.get("/users", response_model=None)
def get_users(
    limit: str | None = None,
    offset: str | None = None,
    name: str | None = None,
    id: str | None = None,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
):
    limit_value, err = parse_uint_param(limit, "limit", x_session_id)
    if err is not None:
        return err

    offset_value, err = parse_uint_param(offset, "offset", x_session_id)
    if err is not None:
        return err

    query: dict[str, Any] = {}

    if id is not None:
        if not ObjectId.is_valid(id):
            return json_error('invalid "id" field', status.HTTP_400_BAD_REQUEST, x_session_id)
        query["_id"] = ObjectId(id)

    if name is not None:
        query["full_name"] = {"$regex": re.escape(name), "$options": "i"}

    cursor = users_collection.find(query).sort("_id", ASCENDING).skip(offset_value or 0)
    if limit_value and limit_value > 0:
        cursor = cursor.limit(limit_value)

    users = [format_user(doc) for doc in cursor]

    response = JSONResponse(content={"users": users, "count": len(users)}, status_code=status.HTTP_200_OK)
    maybe_attach_existing_session_cookie(response, x_session_id)
    return response


@app.get("/users/{user_id}", response_model=None)
def get_user(
    user_id: str,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
):
    if not ObjectId.is_valid(user_id):
        response = JSONResponse(content={"message": "Not found"}, status_code=status.HTTP_404_NOT_FOUND)
        maybe_attach_existing_session_cookie(response, x_session_id)
        return response

    document = users_collection.find_one({"_id": ObjectId(user_id)})
    if document is None:
        response = JSONResponse(content={"message": "Not found"}, status_code=status.HTTP_404_NOT_FOUND)
        maybe_attach_existing_session_cookie(response, x_session_id)
        return response

    result = format_user(document)
    response = JSONResponse(content=result, status_code=status.HTTP_200_OK)
    maybe_attach_existing_session_cookie(response, x_session_id)
    return response


@app.get("/users/{user_id}/events", response_model=None)
def get_user_events(
    user_id: str,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
):
    if not ObjectId.is_valid(user_id):
        response = JSONResponse(content={"message": "User not found"}, status_code=status.HTTP_404_NOT_FOUND)
        maybe_attach_existing_session_cookie(response, x_session_id)
        return response

    user_doc = users_collection.find_one({"_id": ObjectId(user_id)})
    if user_doc is None:
        response = JSONResponse(content={"message": "User not found"}, status_code=status.HTTP_404_NOT_FOUND)
        maybe_attach_existing_session_cookie(response, x_session_id)
        return response

    events = [format_event(doc) for doc in events_collection.find({"created_by": user_id}).sort("_id", ASCENDING)]

    response = JSONResponse(content={"events": events, "count": len(events)}, status_code=status.HTTP_200_OK)
    maybe_attach_existing_session_cookie(response, x_session_id)
    return response


if __name__ == "__main__":
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)

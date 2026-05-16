import hashlib
import uuid
import os
import re
import secrets
import sys
import time as _time
from datetime import datetime, timezone
from typing import Any, Final

import bcrypt
import redis
import uvicorn
from cassandra import ConsistencyLevel
from cassandra.auth import PlainTextAuthProvider
from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement
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
APP_LIKE_TTL = int(get_env_variable("APP_LIKE_TTL"))
APP_EVENT_REVIEWS_TTL = int(get_env_variable("APP_EVENT_REVIEWS_TTL"))
CASSANDRA_HOSTS = get_env_variable("CASSANDRA_HOSTS").split(",")
CASSANDRA_PORT = int(get_env_variable("CASSANDRA_PORT"))
CASSANDRA_USERNAME = os.getenv("CASSANDRA_USERNAME")
CASSANDRA_PASSWORD = os.getenv("CASSANDRA_PASSWORD")
CASSANDRA_KEYSPACE = get_env_variable("CASSANDRA_KEYSPACE")
CASSANDRA_CONSISTENCY = get_env_variable("CASSANDRA_CONSISTENCY")

redis_client = redis.Redis(
    password=REDIS_PASSWORD or None,
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True,
)

mongo_uri = (
    f"mongodb://{MONGODB_USER}:{MONGODB_PASSWORD}"
    f"@{MONGODB_HOST}:{MONGODB_PORT}/{MONGODB_DATABASE}"
)
mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)

database = mongo_client[MONGODB_DATABASE]
users_collection: Collection = database["users"]
events_collection: Collection = database["events"]

def get_cassandra_consistency() -> int:
    from cassandra import ConsistencyLevel

    return getattr(ConsistencyLevel, CASSANDRA_CONSISTENCY)


auth_provider = None
if CASSANDRA_USERNAME and CASSANDRA_PASSWORD:
    auth_provider = PlainTextAuthProvider(
        username=CASSANDRA_USERNAME,
        password=CASSANDRA_PASSWORD,
    )

cassandra_cluster = None
cassandra_session = None

for _attempt in range(60):
    try:
        cassandra_cluster = Cluster(
            contact_points=CASSANDRA_HOSTS,
            port=CASSANDRA_PORT,
            auth_provider=auth_provider,
        )

        cassandra_session = cassandra_cluster.connect()

        cassandra_session.execute(
            f"""
            CREATE KEYSPACE IF NOT EXISTS {CASSANDRA_KEYSPACE}
            WITH replication = {{
                'class': 'SimpleStrategy',
                'replication_factor': 1
            }}
            """
        )

        cassandra_session.set_keyspace(CASSANDRA_KEYSPACE)

        cassandra_session.execute(
            """
            CREATE TABLE IF NOT EXISTS event_reactions (
                event_id text,
                created_by text,
                like_value tinyint,
                created_at timestamp,
                PRIMARY KEY ((event_id), created_by)
            )
            """
        )

        cassandra_session.execute(
            """
            CREATE INDEX IF NOT EXISTS event_reactions_like_value_idx
            ON event_reactions (like_value)
            """
        )

        cassandra_session.execute(
            """
            CREATE TABLE IF NOT EXISTS event_reviews (
                event_id text,
                created_at timestamp,
                id uuid,
                created_by text,
                rating tinyint,
                comment text,
                updated_at timestamp,
                PRIMARY KEY ((event_id), created_at, id)
            ) WITH CLUSTERING ORDER BY (created_at DESC)
            """
        )

        cassandra_session.execute(
            """
            CREATE INDEX IF NOT EXISTS event_reviews_created_by_idx
            ON event_reviews (created_by)
            """
        )

        cassandra_session.execute(
            """
            CREATE INDEX IF NOT EXISTS event_reviews_id_idx
            ON event_reviews (id)
            """
        )

        print("Cassandra ready", file=sys.stderr)
        break
    except Exception as e:
        print(f"Waiting for Cassandra... attempt {_attempt + 1}: {e}", file=sys.stderr)

        if cassandra_cluster is not None:
            cassandra_cluster.shutdown()

        cassandra_session = None
        cassandra_cluster = None
        _time.sleep(5)

if cassandra_session is None:
    print("ERROR: Cassandra is not ready", file=sys.stderr)
    sys.exit(1)


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

def parse_include(include: str | None) -> set[str]:
    if include is None:
        return set()
    return {item.strip() for item in include.split(",") if item.strip()}


def attach_includes_to_event(event: dict[str, Any], include: str | None) -> dict[str, Any]:
    include_values = parse_include(include)

    if "reactions" in include_values:
        event = attach_reactions(event)

    if "reviews" in include_values:
        event = attach_reviews_summary(event)

    return event

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


def zero_reactions() -> dict[str, int]:
    return {"likes": 0, "dislikes": 0}


def reaction_cache_key(title: str) -> str:
    title_hash = hashlib.md5(title.encode("utf-8")).hexdigest()
    return f"event:{title_hash}:reactions"


def get_reaction_event_ids_by_title(title: str) -> list[str]:
    docs = events_collection.find({"title": title}, {"_id": 1})
    return [str(doc["_id"]) for doc in docs]


def get_reactions_from_cassandra(event_ids: list[str]) -> dict[str, int]:
    if not event_ids:
        return zero_reactions()

    likes = 0
    dislikes = 0
    statement = SimpleStatement(
        "SELECT like_value FROM event_reactions WHERE event_id = %s",
        consistency_level=get_cassandra_consistency(),
    )

    for event_id in event_ids:
        rows = cassandra_session.execute(statement, (event_id,))
        for row in rows:
            if row.like_value == 1:
                likes += 1
            elif row.like_value == -1:
                dislikes += 1

    return {"likes": likes, "dislikes": dislikes}


def get_reactions_by_title(title: str) -> dict[str, int]:
    key = reaction_cache_key(title)

    try:
        cached = redis_client.hgetall(key)
    except redis.ResponseError:
        redis_client.delete(key)
        cached = {}

    if cached:
        return {
            "likes": int(cached.get("likes", 0)),
            "dislikes": int(cached.get("dislikes", 0)),
        }

    event_ids = get_reaction_event_ids_by_title(title)
    reactions = get_reactions_from_cassandra(event_ids)

    if reactions["likes"] > 0 or reactions["dislikes"] > 0:
        redis_client.hset(key, mapping=reactions)
        redis_client.expire(key, APP_LIKE_TTL)

    return reactions


def attach_reactions(event: dict[str, Any]) -> dict[str, Any]:
    event["reactions"] = get_reactions_by_title(event.get("title", ""))
    return event


def invalidate_reactions_cache(title: str) -> None:
    event_ids = get_reaction_event_ids_by_title(title)
    reactions = get_reactions_from_cassandra(event_ids)

    key = reaction_cache_key(title)
    redis_client.delete(key)
    redis_client.hset(key, mapping=reactions)
    redis_client.expire(key, APP_LIKE_TTL)

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

    result = events_collection.insert_one(event_document)

    response = JSONResponse(content={"id": str(result.inserted_id)}, status_code=status.HTTP_201_CREATED)
    set_session_cookie(response, sid)
    return response

@app.get("/events", response_model=None)
def get_events(
    title: str | None = None,
    include: str | None = None,
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
    events = [attach_includes_to_event(event, include) for event in events]

    response = JSONResponse(content={"events": events, "count": len(events)}, status_code=status.HTTP_200_OK)
    maybe_attach_existing_session_cookie(response, x_session_id)
    return response


@app.get("/events/{event_id}", response_model=None)
def get_event(
    event_id: str,
    include: str | None = None,
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
    result = attach_includes_to_event(result, include)

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
    title: str | None = None,
    include: str | None = None,
    limit: str | None = None,
    offset: str | None = None,
    id: str | None = None,
    category: str | None = None,
    price_from: str | None = None,
    price_to: str | None = None,
    city: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
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

    limit_value, err = parse_uint_param(limit, "limit", x_session_id)
    if err is not None:
        return err

    offset_value, err = parse_uint_param(offset, "offset", x_session_id)
    if err is not None:
        return err

    query: dict[str, Any] = {
        "created_by": user_id
    }

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
            date_conditions["$gte"] = dt_from.strftime("%Y-%m-%dT00:00:00")

    if date_to is not None:
        dt_to, err = parse_yyyymmdd(date_to, "date_to", x_session_id)
        if err is not None:
            return err
        if dt_to is not None:
            date_conditions["$lte"] = dt_to.strftime("%Y-%m-%dT23:59:59")

    if date_conditions:
        query["started_at"] = date_conditions

    cursor = events_collection.find(query).sort("_id", ASCENDING).skip(offset_value or 0)
    if limit_value and limit_value > 0:
        cursor = cursor.limit(limit_value)

    events = [format_event(doc) for doc in cursor]
    events = [attach_includes_to_event(event, include) for event in events]

    response = JSONResponse(content={"events": events, "count": len(events)}, status_code=status.HTTP_200_OK)
    maybe_attach_existing_session_cookie(response, x_session_id)
    return response


def authorized_user_id_from_session(sid: str | None) -> str | None:
    session_data = get_session_data(sid)
    if not session_data:
        return None
    return session_data.get("user_id")


def set_event_reaction(event_id: str, user_id: str, like_value: int) -> None:
    statement = SimpleStatement(
        """
        INSERT INTO event_reactions (event_id, created_by, like_value, created_at)
        VALUES (%s, %s, %s, %s)
        """,
        consistency_level=get_cassandra_consistency(),
    )
    cassandra_session.execute(
        statement,
        (
            event_id,
            user_id,
            like_value,
            datetime.now(timezone.utc),
        ),
    )


def react_to_event(event_id: str, like_value: int, x_session_id: str | None) -> Response:
    sid = maybe_refresh_post_session(x_session_id)
    user_id = authorized_user_id_from_session(sid)

    if sid is None or user_id is None:
        return Response(content=b"", status_code=status.HTTP_401_UNAUTHORIZED)

    if not ObjectId.is_valid(event_id):
        return json_error("Event not found", status.HTTP_404_NOT_FOUND, sid)

    event = events_collection.find_one({"_id": ObjectId(event_id)})
    if event is None:
        return json_error("Event not found", status.HTTP_404_NOT_FOUND, sid)

    set_event_reaction(event_id, user_id, like_value)
    invalidate_reactions_cache(event.get("title", ""))

    return empty_response(status.HTTP_204_NO_CONTENT, sid)


@app.post("/events/{event_id}/like")
def like_event(
    event_id: str,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> Response:
    return react_to_event(event_id, 1, x_session_id)


@app.post("/events/{event_id}/dislike")
def dislike_event(
    event_id: str,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> Response:
    return react_to_event(event_id, -1, x_session_id)

def find_event_or_error(event_id: str, sid: str | None) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    if not ObjectId.is_valid(event_id):
        return None, json_error("Event not found", status.HTTP_404_NOT_FOUND, sid)

    event = events_collection.find_one({"_id": ObjectId(event_id)})
    if event is None:
        return None, json_error("Event not found", status.HTTP_404_NOT_FOUND, sid)

    return event, None


def user_review_exists(event_id: str, user_id: str) -> bool:
    statement = SimpleStatement(
        """
        SELECT id FROM event_reviews
        WHERE event_id = %s AND created_by = %s
        ALLOW FILTERING
        """,
        consistency_level=get_cassandra_consistency(),
    )
    rows = cassandra_session.execute(statement, (event_id, user_id))
    return rows.one() is not None


@app.post("/events/{event_id}/reviews")
async def create_event_review(
    request: Request,
    event_id: str,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> Response:
    sid = maybe_refresh_post_session(x_session_id)
    user_id = authorized_user_id_from_session(sid)

    if sid is None or user_id is None:
        return Response(content=b"", status_code=status.HTTP_401_UNAUTHORIZED)

    event, error = find_event_or_error(event_id, sid)
    if error is not None:
        return error

    body = parse_json_body(await request.body())
    if body is None:
        return json_error('invalid "comment" field', status.HTTP_400_BAD_REQUEST, sid)

    comment = validate_review_comment(body.get("comment"))
    if comment is None:
        return json_error('invalid "comment" field', status.HTTP_400_BAD_REQUEST, sid)

    rating = validate_review_rating(body.get("rating"))
    if rating is None:
        return json_error('invalid "rating" field', status.HTTP_400_BAD_REQUEST, sid)

    if user_review_exists(event_id, user_id):
        return json_error("Already exists", status.HTTP_409_CONFLICT, sid)

    review_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    statement = SimpleStatement(
        """
        INSERT INTO event_reviews
        (event_id, created_at, id, created_by, rating, comment, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        consistency_level=get_cassandra_consistency(),
    )
    cassandra_session.execute(
        statement,
        (event_id, now, review_id, user_id, rating, comment, now),
    )

    save_reviews_cache(event.get("title", ""))

    response = JSONResponse(content={"id": str(review_id)}, status_code=status.HTTP_201_CREATED)
    set_session_cookie(response, sid)
    return response


@app.get("/events/{event_id}/reviews", response_model=None)
def get_event_reviews(
    event_id: str,
    limit: str | None = None,
    offset: str | None = None,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
):
    limit_value, err = parse_uint_param(limit, "limit", x_session_id)
    if err is not None:
        return err

    offset_value, err = parse_uint_param(offset, "offset", x_session_id)
    if err is not None:
        return err

    event, error = find_event_or_error(event_id, x_session_id)
    if error is not None:
        return error

    statement = SimpleStatement(
        "SELECT * FROM event_reviews WHERE event_id = %s",
        consistency_level=get_cassandra_consistency(),
    )
    rows = list(cassandra_session.execute(statement, (event_id,)))

    start = offset_value or 0
    end = None if not limit_value else start + limit_value

    reviews = [format_review(row) for row in rows[start:end]]

    response = JSONResponse(content={"reviews": reviews, "count": len(reviews)}, status_code=status.HTTP_200_OK)
    maybe_attach_existing_session_cookie(response, x_session_id)
    return response


@app.patch("/events/{event_id}/reviews/{review_id}")
async def patch_event_review(
    request: Request,
    event_id: str,
    review_id: str,
    x_session_id: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> Response:
    sid = maybe_refresh_post_session(x_session_id)
    user_id = authorized_user_id_from_session(sid)

    if sid is None or user_id is None:
        return Response(content=b"", status_code=status.HTTP_401_UNAUTHORIZED)

    event, error = find_event_or_error(event_id, sid)
    if error is not None:
        return error

    try:
        parsed_review_id = uuid.UUID(review_id)
    except ValueError:
        return json_error("Event not found", status.HTTP_404_NOT_FOUND, sid)

    statement = SimpleStatement(
        """
        SELECT * FROM event_reviews
        WHERE event_id = %s AND id = %s
        ALLOW FILTERING
        """,
        consistency_level=get_cassandra_consistency(),
    )
    row = cassandra_session.execute(statement, (event_id, parsed_review_id)).one()

    if row is None or row.created_by != user_id:
        return json_error("Event not found", status.HTTP_404_NOT_FOUND, sid)

    body = parse_json_body(await request.body())
    if body is None:
        return json_error('invalid "body" field', status.HTTP_400_BAD_REQUEST, sid)

    new_comment = row.comment
    new_rating = int(row.rating)

    if "comment" in body:
        comment = validate_review_comment(body.get("comment"))
        if comment is None:
            return json_error('invalid "comment" field', status.HTTP_400_BAD_REQUEST, sid)
        new_comment = comment

    if "rating" in body:
        rating = validate_review_rating(body.get("rating"))
        if rating is None:
            return json_error('invalid "rating" field', status.HTTP_400_BAD_REQUEST, sid)
        new_rating = rating

    update_statement = SimpleStatement(
        """
        UPDATE event_reviews
        SET comment = %s, rating = %s, updated_at = %s
        WHERE event_id = %s AND created_at = %s AND id = %s
        """,
        consistency_level=get_cassandra_consistency(),
    )
    cassandra_session.execute(
        update_statement,
        (
            new_comment,
            new_rating,
            datetime.now(timezone.utc),
            event_id,
            row.created_at,
            parsed_review_id,
        ),
    )

    save_reviews_cache(event.get("title", ""))

    return empty_response(status.HTTP_204_NO_CONTENT, sid)


def reviews_cache_key(title: str) -> str:
    title_hash = hashlib.md5(title.encode("utf-8")).hexdigest()
    return f"event:{title_hash}:reviews"


def zero_reviews_summary() -> dict[str, int | float]:
    return {"count": 0, "rating": 0.0}


def get_review_event_ids_by_title(title: str) -> list[str]:
    docs = events_collection.find({"title": title}, {"_id": 1})
    return [str(doc["_id"]) for doc in docs]


def round_rating(value: float) -> float:
    return round(value + 1e-8, 1)


def get_reviews_summary_from_cassandra(event_ids: list[str]) -> dict[str, int | float]:
    if not event_ids:
        return zero_reviews_summary()

    total_count = 0
    rating_sum = 0

    statement = SimpleStatement(
        "SELECT rating FROM event_reviews WHERE event_id = %s",
        consistency_level=get_cassandra_consistency(),
    )

    for event_id in event_ids:
        rows = cassandra_session.execute(statement, (event_id,))
        for row in rows:
            total_count += 1
            rating_sum += int(row.rating)

    if total_count == 0:
        return zero_reviews_summary()

    return {
        "count": total_count,
        "rating": round_rating(rating_sum / total_count),
    }


def get_reviews_summary_by_title(title: str) -> dict[str, int | float]:
    key = reviews_cache_key(title)

    try:
        cached = redis_client.hgetall(key)
    except redis.ResponseError:
        redis_client.delete(key)
        cached = {}

    if cached:
        return {
            "count": int(cached.get("count", 0)),
            "rating": float(cached.get("rating", 0.0)),
        }

    event_ids = get_review_event_ids_by_title(title)
    summary = get_reviews_summary_from_cassandra(event_ids)

    if int(summary["count"]) > 0:
        redis_client.hset(key, mapping=summary)
        redis_client.expire(key, APP_EVENT_REVIEWS_TTL)

    return summary


def save_reviews_cache(title: str) -> None:
    event_ids = get_review_event_ids_by_title(title)
    summary = get_reviews_summary_from_cassandra(event_ids)

    key = reviews_cache_key(title)
    redis_client.delete(key)
    redis_client.hset(key, mapping=summary)
    redis_client.expire(key, APP_EVENT_REVIEWS_TTL)


def attach_reviews_summary(event: dict[str, Any]) -> dict[str, Any]:
    event["reviews"] = get_reviews_summary_by_title(event.get("title", ""))
    return event


def format_review(row: Any) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "event_id": row.event_id,
        "comment": row.comment,
        "created_at": row.created_at.replace(tzinfo=timezone.utc).isoformat(),
        "created_by": row.created_by,
        "rating": int(row.rating),
        "updated_at": row.updated_at.replace(tzinfo=timezone.utc).isoformat(),
    }


def validate_review_comment(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if len(value) > 300:
        return None
    return value


def validate_review_rating(value: Any) -> int | None:
    if not isinstance(value, int):
        return None
    if value < 1 or value > 5:
        return None
    return value

if __name__ == "__main__":
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)

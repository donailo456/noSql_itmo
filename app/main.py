import os
import sys
from fastapi import FastAPI
import uvicorn

app = FastAPI()


@app.get("/health")
def healthcheck():
    return {"status": "ok"}


def get_env_variable(name: str) -> str:
    value = os.getenv(name)
    if not value:
        print(f"ERROR: {name} is not set", file=sys.stderr)
        sys.exit(1)
    return value


if __name__ == "__main__":
    host = get_env_variable("APP_HOST")
    port = int(get_env_variable("APP_PORT"))

    uvicorn.run(app, host=host, port=port)
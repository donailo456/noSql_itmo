import os
from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/health")
def healthcheck():
    return {"status": "ok"}

if __name__ == "__main__":
    port = int(os.getenv("APP_PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
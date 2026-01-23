# main.py
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import engine
from models import Base
from auth_routes import router as auth_router

app = FastAPI(title="UniversalNews Auth API", version="0.1.0")

# Create tables (OK for now; later we can move to migrations)
Base.metadata.create_all(bind=engine)

ALLOWED_ORIGINS = [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://panashe816.github.io",  # <-- your GitHub Pages
]

# Optional: if you have a custom domain for pages, add it here too.
# e.g. "https://yourdomain.com"

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)

@app.get("/")
def root():
    return {"ok": True, "service": "auth"}

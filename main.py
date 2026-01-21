# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import engine
from models import Base
from auth_routes import router as auth_router

app = FastAPI(title="UniversalNews Auth API")

# Create tables if missing (your users table already exists, so this is safe)
Base.metadata.create_all(bind=engine)

# Allow frontend to call locally (adjust origins later)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)

@app.get("/")
def root():
    return {"status": "ok", "message": "Auth backend running"}

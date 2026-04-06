from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import predict, threats, reports
from app.core.config import settings

app = FastAPI(
    title="PhishSense API",
    description="Real-Time Multimodal Phishing Defense Backend",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(predict.router, prefix="/api/v1", tags=["prediction"])
app.include_router(threats.router, prefix="/api/v1", tags=["threats"])
app.include_router(reports.router, prefix="/api/v1", tags=["reports"])


@app.get("/health")
async def health_check():
    return {"status": "healthy"}

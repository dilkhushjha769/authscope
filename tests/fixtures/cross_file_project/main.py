"""Main application entry point for cross-file static analysis testing."""

from fastapi import FastAPI
from auth.middleware import GlobalSecurityMiddleware
from routers.protected_routes import router as protected_router
from routers.unprotected_routes import router as unprotected_router
from routers.uncertain_routes import router as uncertain_router

app = FastAPI()
app.add_middleware(GlobalSecurityMiddleware)
app.include_router(protected_router)
app.include_router(unprotected_router)
app.include_router(uncertain_router)


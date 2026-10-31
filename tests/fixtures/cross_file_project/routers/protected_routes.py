"""Protected routes utilizing cross-file authorization decorators and dependencies."""

from fastapi import APIRouter, Depends
from ..auth.decorators import require_admin
from ..auth.dependencies import get_current_admin
from ..auth.helpers import verify_admin_access

router = APIRouter(prefix="/admin/protected")


# Route 1: Protected via imported custom decorator
@router.post("/export-database")
@require_admin
async def export_database():
    return {"status": "exported"}


# Route 2: Protected via imported FastAPI dependency
@router.get("/system-settings")
async def get_system_settings(admin=Depends(get_current_admin)):
    return {"settings": "sensitive_config"}


# Route 3: Protected via imported in-body auth check
@router.delete("/purge-users")
async def purge_users(role: str):
    verify_admin_access(role)
    return {"status": "purged"}


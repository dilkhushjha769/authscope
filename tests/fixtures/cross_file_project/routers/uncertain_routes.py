"""Routes using external unresolvable security dependencies."""

from fastapi import APIRouter
from third_party_security_provider import enterprise_guard

router = APIRouter()


# Route referencing an unresolvable external module -> Must trigger INCONCLUSIVE analysis uncertainty
@router.post("/admin/external-guarded")
@enterprise_guard
async def external_guarded():
    return {"status": "secure"}


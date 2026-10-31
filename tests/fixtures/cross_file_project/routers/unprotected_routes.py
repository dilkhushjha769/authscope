"""Unprotected privileged routes representing genuine BFLA vulnerabilities."""

from fastapi import APIRouter

router = APIRouter()


# Genuine Broken Access Control (BFLA): Privileged administrative route with NO security controls!
@router.post("/admin/nuclear-reset")
async def nuclear_reset():
    return {"status": "wiped"}


"""Persistence and data model for dual-connection projects (GitHub OAuth and Website URL)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field

from backend.storage.database import DatabaseManager


class ProjectRecord(BaseModel):
    """Represents a connected application project in AuthScope."""

    id: str = Field(default_factory=lambda: f"proj_{uuid.uuid4().hex[:12]}")
    name: str = Field(..., description="Human-readable project title or repository name")
    project_type: str = Field(..., description="'github' or 'website'")
    user_id: str = Field(..., description="ID of the user who owns this project")
    target_url: Optional[str] = Field(default=None, description="Deployed web URL (for website projects)")
    github_repo_full_name: Optional[str] = Field(default=None, description="owner/repo (for GitHub projects)")
    github_installation_id: Optional[int] = Field(default=None, description="Installation ID for GitHub App")
    github_default_branch: str = Field(default="main", description="Target branch")
    is_private: bool = Field(default=False, description="Whether GitHub repository is private")
    authorization_status: str = Field(default="AUTHORIZED", description="'AUTHORIZED' or 'PENDING'")
    authorization_basis: str = Field(default="admin_approved", description="Grounds for security testing authorization")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ProjectRepository:
    """Stores and retrieves ProjectRecord items with user ownership isolation."""

    def __init__(self, database: Optional[DatabaseManager] = None) -> None:
        self.database = database or DatabaseManager()

    def create_project(self, project: ProjectRecord) -> ProjectRecord:
        """Inserts a new project into the SQLite store."""
        with self.database.session_scope() as conn:
            conn.execute(
                """INSERT INTO projects (
                    id, name, project_type, user_id, target_url, github_repo_full_name,
                    github_installation_id, github_default_branch, is_private,
                    authorization_status, authorization_basis, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    project.id,
                    project.name,
                    project.project_type,
                    project.user_id,
                    project.target_url,
                    project.github_repo_full_name,
                    project.github_installation_id,
                    project.github_default_branch,
                    1 if project.is_private else 0,
                    project.authorization_status,
                    project.authorization_basis,
                    project.created_at,
                    project.updated_at,
                ),
            )
        return project

    def get_project(self, project_id: str) -> Optional[ProjectRecord]:
        """Retrieves a project by its primary ID."""
        with self.database.session_scope() as conn:
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["is_private"] = bool(d.get("is_private", 0))
        return ProjectRecord(**d)

    def list_projects(self, user_id: str) -> List[ProjectRecord]:
        """Lists projects owned by a specific user."""
        with self.database.session_scope() as conn:
            rows = conn.execute(
                "SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
            ).fetchall()
        projects: List[ProjectRecord] = []
        for r in rows:
            d = dict(r)
            d["is_private"] = bool(d.get("is_private", 0))
            projects.append(ProjectRecord(**d))
        return projects

    def delete_project(self, project_id: str, user_id: str) -> bool:
        """Deletes a project only if owned by the specified user."""
        with self.database.session_scope() as conn:
            cursor = conn.execute(
                "DELETE FROM projects WHERE id = ? AND user_id = ?", (project_id, user_id)
            )
            return cursor.rowcount > 0


"""Synthetic Python vulnerable source fixture for SourceAnalyzer unit tests."""

import os
import subprocess
import sqlite3
import yaml
import jwt
from flask import Flask, request, render_template_string, make_response
from markupsafe import Markup

app = Flask(__name__)

# 1. Sensitive Data Exposure (Hardcoded Secret)
SECRET_KEY = "sk_live_synthetic_hardcoded_secret_987654321"
DB_PASSWORD = "super_secret_db_password_123!"

# 2. Security Misconfiguration (Debug enabled)
DEBUG = True


@app.route("/api/users/search", methods=["GET"])
def search_users_sqli():
    """SQL Injection via f-string and string concatenation."""
    username = request.args.get("username", "")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT id, email, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return {"results": cursor.fetchall()}


@app.route("/profile/preview", methods=["GET"])
def preview_profile_xss():
    """Cross-Site Scripting via render_template_string and Markup."""
    bio = request.args.get("bio", "")
    rendered = render_template_string(f"<div class='bio'>{bio}</div>")
    unsafe_badge = Markup(f"<span>{bio}</span>")
    return make_response(rendered + str(unsafe_badge))


@app.route("/api/admin/delete_all", methods=["POST"])
def admin_purge_system():
    """Broken Access Control (BFLA): Privileged admin route without auth decorator or role check."""
    return {"status": "purged"}


@app.route("/api/role/update", methods=["POST"])
def update_user_role():
    """Broken Access Control: Trusting client-supplied role flag and unverified JWT."""
    token = request.headers.get("Authorization", "")
    claims = jwt.decode(token, options={"verify_signature": False})
    new_role = request.json.get("is_admin")
    return {"updated": new_role, "sub": claims.get("sub")}


@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order_idor(order_id: int):
    """IDOR / BOLA: Direct object lookup by order_id without verifying current_user ownership."""
    order = OrderModel.query.get(order_id)
    return {"order": order}


def unsafe_system_helpers(user_cmd: str, yaml_payload: str):
    """Security Misconfiguration: shell=True, yaml.load without SafeLoader, eval."""
    subprocess.run(user_cmd, shell=True)
    data = yaml.load(yaml_payload)
    return eval("1 + 1"), data


"""Synthetic Python SAFE source fixture for false-positive prevention tests."""

import os
import sqlite3
import subprocess
import html
import yaml
import jwt
from flask import Flask, request, render_template, jsonify, abort

app = Flask(__name__)

# Safe configuration via environment variables and placeholders
SECRET_KEY = os.environ.get("APP_SECRET_KEY", "")
API_KEY_HEADER = "X-API-Key"
PASSWORD_PLACEHOLDER = "placeholder"
DEBUG = False


def login_required(fn):
    return fn


def admin_required(fn):
    return fn


@app.route("/api/users/search", methods=["GET"])
@login_required
def search_users_safe():
    """Safe parameterized SQL query."""
    username = request.args.get("username", "")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT id, email FROM users WHERE username = ?", (username,))
    return jsonify({"results": cursor.fetchall()})


@app.route("/profile/preview", methods=["GET"])
@login_required
def preview_profile_safe():
    """Safe template rendering with escaped context variable."""
    bio = html.escape(request.args.get("bio", ""))
    return render_template("profile.html", bio=bio)


@app.route("/api/admin/metrics", methods=["GET"])
@login_required
@admin_required
def admin_metrics_safe(current_user):
    """Safe admin route with explicit decorator and role check."""
    if not current_user.is_admin:
        abort(403)
    return jsonify({"metrics": "ok"})


@app.route("/api/orders/<int:order_id>", methods=["GET"])
@login_required
def get_order_safe(order_id: int, current_user):
    """Safe object lookup scoped to authenticated owner user_id."""
    order = OrderModel.query.filter_by(id=order_id, user_id=current_user.id).first()
    if not order or order.owner_id != current_user.id:
        abort(403)
    return jsonify({"order": order.to_dict()})


def safe_helpers(args_list: list[str], yaml_payload: str, token: str, pub_key: str):
    """Safe subprocess, SafeLoader YAML, and verified JWT decode."""
    subprocess.run(["echo", *args_list], shell=False, check=False)
    data = yaml.safe_load(yaml_payload)
    claims = jwt.decode(token, pub_key, algorithms=["RS256"])
    return data, claims


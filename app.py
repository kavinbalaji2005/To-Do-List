import base64
import hashlib
import hmac
import os
import boto3
from functools import wraps
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///todo.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    cognito_sub = db.Column(db.String(128), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    lists = db.relationship("TodoList", backref="owner", cascade="all, delete-orphan", lazy=True)


class TodoList(db.Model):
    __tablename__ = "todo_lists"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    items = db.relationship(
        "ChecklistItem",
        backref="todo_list",
        cascade="all, delete-orphan",
        lazy=True,
        order_by="ChecklistItem.id.asc()",
    )

    @property
    def total_items(self):
        return len(self.items)

    @property
    def completed_items(self):
        return sum(1 for item in self.items if item.completed)

    def to_dict(self, include_items=False):
        payload = {
            "id": self.id,
            "name": self.name,
            "total_items": self.total_items,
            "completed_items": self.completed_items,
            "progress_label": f"{self.completed_items} of {self.total_items} items completed",
        }
        if include_items:
            payload["items"] = [item.to_dict() for item in self.items]
        return payload

class ChecklistItem(db.Model):
    __tablename__ = "checklist_items"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, nullable=False, default=False)
    list_id = db.Column(db.Integer, db.ForeignKey("todo_lists.id"), nullable=False, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "completed": self.completed,
            "list_id": self.list_id,
        }

def _cognito_settings():
    region = os.getenv("AWS_REGION", "").strip()
    client_id = os.getenv("COGNITO_APP_CLIENT_ID", "").strip()
    client_secret = os.getenv("COGNITO_APP_CLIENT_SECRET", "").strip()
    if not region or not client_id:
        raise RuntimeError(
            "Cognito is not configured. Set AWS_REGION and COGNITO_APP_CLIENT_ID in your environment."
        )
    return region, client_id, client_secret

def _cognito_client(region):
    return boto3.client("cognito-idp", region_name=region)

def _secret_hash(username, client_id, client_secret):
    if not client_secret:
        return None
    digest = hmac.new(
        client_secret.encode("utf-8"),
        f"{username}{client_id}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode("utf-8")

def _cognito_error_message(error):
    return error.response.get("Error", {}).get("Message", "Unexpected Cognito error.")

def current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return db.session.get(User, user_id)

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped

def api_login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        user = _api_current_user()
        if user is None:
            return jsonify({"error": "Authentication required"}), 401
        g.api_user = user
        return view_func(*args, **kwargs)
    return wrapped

def _api_current_user():
    user = current_user()
    if user is not None:
        return user
    auth_header = request.headers.get("Authorization", "").strip()
    if not auth_header.startswith("Bearer "):
        return None
    access_token = auth_header.split(" ", 1)[1].strip()
    if not access_token:
        return None
    try:
        region, _, _ = _cognito_settings()
        client = _cognito_client(region)
        cognito_user = client.get_user(AccessToken=access_token)
    except (RuntimeError, ClientError):
        return None

    attributes = {attr["Name"]: attr["Value"] for attr in cognito_user.get("UserAttributes", [])}
    cognito_sub = attributes.get("sub", cognito_user["Username"])
    user_email = attributes.get("email", cognito_user["Username"])

    user = User.query.filter_by(cognito_sub=cognito_sub).first()
    if user is None:
        user = User(cognito_sub=cognito_sub, email=user_email)
        db.session.add(user)
    else:
        user.email = user_email
    db.session.commit()
    return user

def _get_user_list_or_404(user_id, list_id):
    todo_list = TodoList.query.filter_by(id=list_id, user_id=user_id).first()
    if todo_list is None:
        abort(404)
    return todo_list

def _get_user_item_or_404(user_id, item_id):
    item = (
        ChecklistItem.query.join(TodoList, ChecklistItem.list_id == TodoList.id)
        .filter(ChecklistItem.id == item_id, TodoList.user_id == user_id)
        .first()
    )
    if item is None:
        abort(404)
    return item

@app.context_processor
def inject_session_user():
    return {"session_user": current_user()}

@app.get("/")
def home():
    if current_user() is not None:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user() is not None:
        return redirect(url_for("dashboard"))

    default_email = session.get("pending_username", "")
    step = "confirm" if default_email else "signup"

    if request.method == "POST":
        stage = request.form.get("stage", "signup").strip().lower()

        if stage == "signup":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not email or not password:
                flash("Email and password are required.", "danger")
                return render_template("register.html", step="signup", default_email=email)

            try:
                region, client_id, client_secret = _cognito_settings()
                client = _cognito_client(region)

                payload = {
                    "ClientId": client_id,
                    "Username": email,
                    "Password": password,
                    "UserAttributes": [{"Name": "email", "Value": email}],
                }
                secret_hash = _secret_hash(email, client_id, client_secret)
                if secret_hash:
                    payload["SecretHash"] = secret_hash

                client.sign_up(**payload)
                session["pending_username"] = email
                flash("Verification code sent. Enter it below to finish signup.", "success")
                return render_template("register.html", step="confirm", default_email=email)
            except RuntimeError as error:
                flash(str(error), "danger")
            except ClientError as error:
                flash(_cognito_error_message(error), "danger")
            return render_template("register.html", step="signup", default_email=email)

        if stage == "confirm":
            username = request.form.get("username", default_email).strip().lower()
            code = request.form.get("code", "").strip()

            if not username or not code:
                flash("Email and verification code are required.", "danger")
                return render_template("register.html", step="confirm", default_email=username or default_email)

            try:
                region, client_id, client_secret = _cognito_settings()
                client = _cognito_client(region)

                payload = {
                    "ClientId": client_id,
                    "Username": username,
                    "ConfirmationCode": code,
                }
                secret_hash = _secret_hash(username, client_id, client_secret)
                if secret_hash:
                    payload["SecretHash"] = secret_hash

                client.confirm_sign_up(**payload)
                session.pop("pending_username", None)
                flash("Account confirmed. You can now sign in.", "success")
                return redirect(url_for("login"))
            except RuntimeError as error:
                flash(str(error), "danger")
            except ClientError as error:
                flash(_cognito_error_message(error), "danger")
            return render_template("register.html", step="confirm", default_email=username or default_email)

        flash("Invalid registration action.", "danger")

    return render_template("register.html", step=step, default_email=default_email)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user() is not None:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "danger")
            return render_template("login.html")

        try:
            region, client_id, client_secret = _cognito_settings()
            client = _cognito_client(region)
            auth_params = {"USERNAME": email, "PASSWORD": password}
            secret_hash = _secret_hash(email, client_id, client_secret)
            if secret_hash:
                auth_params["SECRET_HASH"] = secret_hash

            auth_response = client.initiate_auth(
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters=auth_params,
                ClientId=client_id,
            )
            access_token = auth_response["AuthenticationResult"]["AccessToken"]
            cognito_user = client.get_user(AccessToken=access_token)
            attributes = {attr["Name"]: attr["Value"] for attr in cognito_user.get("UserAttributes", [])}
            cognito_sub = attributes.get("sub", cognito_user["Username"])
            user_email = attributes.get("email", email)

            user = User.query.filter_by(cognito_sub=cognito_sub).first()
            if user is None:
                user = User(cognito_sub=cognito_sub, email=user_email)
                db.session.add(user)
            else:
                user.email = user_email
            db.session.commit()

            session["user_id"] = user.id
            session["user_email"] = user.email
            return redirect(url_for("dashboard"))
        except RuntimeError as error:
            flash(str(error), "danger")
        except ClientError as error:
            flash(_cognito_error_message(error), "danger")

    return render_template("login.html")

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/dashboard")
@login_required
def dashboard():
    user = current_user()
    lists = TodoList.query.filter_by(user_id=user.id).order_by(TodoList.id.desc()).all()
    return render_template("dashboard.html", lists=lists)

@app.post("/lists")
@login_required
def create_list():
    user = current_user()
    name = request.form.get("name", "").strip()
    if not name:
        flash("List name is required.", "danger")
        return redirect(url_for("dashboard"))

    todo_list = TodoList(name=name, user_id=user.id)
    db.session.add(todo_list)
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.post("/lists/<int:list_id>/delete")
@login_required
def delete_list(list_id):
    user = current_user()
    todo_list = _get_user_list_or_404(user.id, list_id)
    db.session.delete(todo_list)
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.get("/lists/<int:list_id>")
@login_required
def view_list(list_id):
    user = current_user()
    todo_list = _get_user_list_or_404(user.id, list_id)
    return render_template("list_view.html", todo_list=todo_list)

@app.post("/lists/<int:list_id>/items")
@login_required
def add_item(list_id):
    user = current_user()
    todo_list = _get_user_list_or_404(user.id, list_id)
    title = request.form.get("title", "").strip()
    if not title:
        flash("Item title is required.", "danger")
        return redirect(url_for("view_list", list_id=todo_list.id))

    item = ChecklistItem(title=title, completed=False, list_id=todo_list.id)
    db.session.add(item)
    db.session.commit()
    return redirect(url_for("view_list", list_id=todo_list.id))

@app.post("/items/<int:item_id>/toggle")
@login_required
def toggle_item(item_id):
    user = current_user()
    item = _get_user_item_or_404(user.id, item_id)
    item.completed = not item.completed
    db.session.commit()
    return redirect(url_for("view_list", list_id=item.list_id))

@app.post("/items/<int:item_id>/delete")
@login_required
def delete_item(item_id):
    user = current_user()
    item = _get_user_item_or_404(user.id, item_id)
    list_id = item.list_id
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for("view_list", list_id=list_id))

@app.get("/api/lists")
@api_login_required
def api_get_lists():
    user = g.api_user
    lists = TodoList.query.filter_by(user_id=user.id).order_by(TodoList.id.desc()).all()
    return jsonify({"lists": [todo_list.to_dict() for todo_list in lists]})

@app.post("/api/lists")
@api_login_required
def api_create_list():
    user = g.api_user
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"error": "Field 'name' is required."}), 400

    todo_list = TodoList(name=name, user_id=user.id)
    db.session.add(todo_list)
    db.session.commit()
    return jsonify(todo_list.to_dict()), 201

@app.get("/api/lists/<int:list_id>")
@api_login_required
def api_get_list(list_id):
    user = g.api_user
    todo_list = _get_user_list_or_404(user.id, list_id)
    return jsonify(todo_list.to_dict(include_items=True))

@app.put("/api/lists/<int:list_id>")
@api_login_required
def api_update_list(list_id):
    user = g.api_user
    todo_list = _get_user_list_or_404(user.id, list_id)
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"error": "Field 'name' is required."}), 400

    todo_list.name = name
    db.session.commit()
    return jsonify(todo_list.to_dict())

@app.delete("/api/lists/<int:list_id>")
@api_login_required
def api_delete_list(list_id):
    user = g.api_user
    todo_list = _get_user_list_or_404(user.id, list_id)
    db.session.delete(todo_list)
    db.session.commit()
    return jsonify({"message": "List deleted successfully."})

@app.post("/api/lists/<int:list_id>/items")
@api_login_required
def api_create_item(list_id):
    user = g.api_user
    todo_list = _get_user_list_or_404(user.id, list_id)
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"error": "Field 'title' is required."}), 400

    completed = bool(data.get("completed", False))
    item = ChecklistItem(title=title, completed=completed, list_id=todo_list.id)
    db.session.add(item)
    db.session.commit()
    db.session.refresh(todo_list)
    return jsonify({"item": item.to_dict(), "list_progress": todo_list.to_dict()}), 201

@app.put("/api/items/<int:item_id>")
@api_login_required
def api_update_item(item_id):
    user = g.api_user
    item = _get_user_item_or_404(user.id, item_id)
    data = request.get_json(silent=True) or {}

    if "title" in data:
        title = str(data.get("title", "")).strip()
        if not title:
            return jsonify({"error": "Field 'title' cannot be empty."}), 400
        item.title = title

    if "completed" in data:
        item.completed = bool(data.get("completed"))

    db.session.commit()
    todo_list = db.session.get(TodoList, item.list_id)
    return jsonify({"item": item.to_dict(), "list_progress": todo_list.to_dict()})

@app.delete("/api/items/<int:item_id>")
@api_login_required
def api_delete_item(item_id):
    user = g.api_user
    item = _get_user_item_or_404(user.id, item_id)
    todo_list = db.session.get(TodoList, item.list_id)
    db.session.delete(item)
    db.session.commit()
    db.session.refresh(todo_list)
    return jsonify({"message": "Item deleted successfully.", "list_progress": todo_list.to_dict()})

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    app.run(debug=True, host="127.0.0.1", port=port)

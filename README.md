# Flask + REST Todo App

Simple todo list app built with Flask, SQLAlchemy, and AWS Cognito auth.

You can use it in two ways:

- Web app (login/register + dashboard UI)
- REST API (`/api/*`) for list/item CRUD

## What it does

- User sign up + confirmation + login with Cognito
- Multiple todo lists per user
- Checklist items inside each list
- Progress tracking (`x of y completed`)
- Rename list and item from the UI
- Session auth for web + Bearer token auth for API

## Stack

- Python + Flask
- Flask-SQLAlchemy
- SQLite by default (local dev)
- AWS Cognito (via `boto3`)
- Bootstrap 5 templates

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
FLASK_SECRET_KEY=replace-with-a-strong-secret
AWS_REGION=ap-south-1
COGNITO_APP_CLIENT_ID=your-cognito-app-client-id
COGNITO_APP_CLIENT_SECRET=your-cognito-app-client-secret
# Optional locally; defaults to sqlite:///todo.db
DATABASE_URL=sqlite:///todo.db
PORT=5001
```

Run:

```bash
python app.py
```

Open `http://127.0.0.1:5001`.

## API quick reference

All API routes require authentication (`session` cookie or `Authorization: Bearer <access_token>`).

| Method | Route                        | Purpose                        |
| ------ | ---------------------------- | ------------------------------ |
| GET    | `/api/lists`                 | Get all lists for current user |
| POST   | `/api/lists`                 | Create a list                  |
| GET    | `/api/lists/<list_id>`       | Get one list + items           |
| PUT    | `/api/lists/<list_id>`       | Rename a list                  |
| DELETE | `/api/lists/<list_id>`       | Delete a list                  |
| POST   | `/api/lists/<list_id>/items` | Add item to list               |
| PUT    | `/api/items/<item_id>`       | Update item title/completed    |
| DELETE | `/api/items/<item_id>`       | Delete item                    |

## Database notes

Default local DB is SQLite (`instance/todo.db`).

Tables:

- `users`
- `todo_lists` (belongs to `users`)
- `checklist_items` (belongs to `todo_lists`)

On startup, tables are created automatically with `db.create_all()`.

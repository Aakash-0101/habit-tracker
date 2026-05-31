# ============================================================
#  HABIT TRACKER — Backend (app.py)
#  Built with: Python + Flask + PostgreSQL
# ============================================================
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import bcrypt
import jwt
import os
import datetime

# ── App setup ───────────────────────────────────────────────
app = Flask(__name__, static_folder='static')
CORS(app)  # Allow frontend to talk to backend

# Secret key used to sign login tokens (change this to anything secret)
SECRET_KEY = os.environ.get('SECRET_KEY', 'mysecretkey123')

# ── Database connection ──────────────────────────────────────
def get_db():
    """Connect to PostgreSQL database."""
    conn = psycopg2.connect(
        os.environ.get('DATABASE_URL'),
        cursor_factory=psycopg2.extras.RealDictCursor
    )
    return conn

def init_db():
    """Create tables if they don't exist yet."""
    conn = get_db()
    cur = conn.cursor()

    # Table 1: users — stores login info
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id        SERIAL PRIMARY KEY,
            userid    VARCHAR(50) UNIQUE NOT NULL,
            name      VARCHAR(100) NOT NULL,
            password  VARCHAR(200) NOT NULL,
            created   TIMESTAMP DEFAULT NOW()
        );
    """)

    # Table 2: habits — each habit belongs to a user
    cur.execute("""
        CREATE TABLE IF NOT EXISTS habits (
            id       SERIAL PRIMARY KEY,
            user_id  INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name     VARCHAR(200) NOT NULL,
            created  TIMESTAMP DEFAULT NOW()
        );
    """)

    # Table 3: checks — each tick on a day for a habit
    cur.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id        SERIAL PRIMARY KEY,
            habit_id  INTEGER REFERENCES habits(id) ON DELETE CASCADE,
            day       INTEGER NOT NULL,
            month     INTEGER NOT NULL,
            year      INTEGER NOT NULL,
            UNIQUE(habit_id, day, month, year)
        );
    """)

    conn.commit()
    cur.close()
    conn.close()

# ── Helper: read token from request header ───────────────────
def get_user_from_token():
    """Read the JWT token and return the user_id."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth.split(' ')[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except:
        return None

# ── Serve the frontend HTML ──────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

# ── API: Register new user ───────────────────────────────────
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    userid   = data.get('userid', '').strip().lower()
    password = data.get('password', '')
    name     = data.get('name', userid)

    if not userid or not password:
        return jsonify({'error': 'Please fill all fields'}), 400

    # Hash the password before saving (never store plain text!)
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (userid, name, password) VALUES (%s, %s, %s) RETURNING id, name",
            (userid, name, hashed)
        )
        user = cur.fetchone()
        conn.commit()

        # Create a login token
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
        }, SECRET_KEY, algorithm='HS256')

        return jsonify({'token': token, 'name': user['name']})

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({'error': 'User ID already taken'}), 409
    finally:
        cur.close()
        conn.close()

# ── API: Login ───────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    data     = request.json
    userid   = data.get('userid', '').strip().lower()
    password = data.get('password', '')

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM users WHERE userid = %s", (userid,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify({
            'error': 'No account found with this User ID. Please create an account first.',
            'code': 'USER_NOT_FOUND'
        }), 404

    # Check password against stored hash
    if not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return jsonify({
            'error': 'Wrong password. Please try again.',
            'code': 'WRONG_PASSWORD'
        }), 401

    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }, SECRET_KEY, algorithm='HS256')

    return jsonify({'token': token, 'name': user['name']})

# ── API: Get all habits for logged-in user ───────────────────
@app.route('/api/habits', methods=['GET'])
def get_habits():
    user_id = get_user_from_token()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id, name FROM habits WHERE user_id = %s ORDER BY created", (user_id,))
    habits = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(habits)

# ── API: Add a new habit ─────────────────────────────────────
@app.route('/api/habits', methods=['POST'])
def add_habit():
    user_id = get_user_from_token()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    name = request.json.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Habit name is required'}), 400

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "INSERT INTO habits (user_id, name) VALUES (%s, %s) RETURNING id, name",
        (user_id, name)
    )
    habit = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(habit)

# ── API: Delete a habit ──────────────────────────────────────
@app.route('/api/habits/<int:habit_id>', methods=['DELETE'])
def delete_habit(habit_id):
    user_id = get_user_from_token()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    conn = get_db()
    cur  = conn.cursor()
    # Only delete if the habit belongs to this user
    cur.execute(
        "DELETE FROM habits WHERE id = %s AND user_id = %s",
        (habit_id, user_id)
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'success': True})

# ── API: Get all checks for a month ─────────────────────────
@app.route('/api/checks', methods=['GET'])
def get_checks():
    user_id = get_user_from_token()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    month = request.args.get('month')
    year  = request.args.get('year')

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT c.habit_id, c.day
        FROM checks c
        JOIN habits h ON h.id = c.habit_id
        WHERE h.user_id = %s AND c.month = %s AND c.year = %s
    """, (user_id, month, year))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)

# ── API: Tick or untick a checkbox ───────────────────────────
@app.route('/api/checks', methods=['POST'])
def toggle_check():
    user_id = get_user_from_token()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    data     = request.json
    habit_id = data.get('habit_id')
    day      = data.get('day')
    month    = data.get('month')
    year     = data.get('year')

    conn = get_db()
    cur  = conn.cursor()

    # Check if already ticked
    cur.execute(
        "SELECT id FROM checks WHERE habit_id=%s AND day=%s AND month=%s AND year=%s",
        (habit_id, day, month, year)
    )
    existing = cur.fetchone()

    if existing:
        # Already ticked → untick (delete)
        cur.execute("DELETE FROM checks WHERE id = %s", (existing['id'],))
        action = 'removed'
    else:
        # Not ticked → tick (insert)
        cur.execute(
            "INSERT INTO checks (habit_id, day, month, year) VALUES (%s,%s,%s,%s)",
            (habit_id, day, month, year)
        )
        action = 'added'

    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'action': action})

# ── Run the app ──────────────────────────────────────────────
if __name__ == '__main__':
    init_db()            # Create tables on first run
    app.run(debug=True)  # Runs on http://localhost:5000

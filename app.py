from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("testing.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def home():
    return "Flask is running!"

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    Username = data["Username"]
    Password = data["Password"]

    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (Username, Password, Role) VALUES (?, ?, ?)",
                  (Username, Password, "user"))
        conn.commit()
        return jsonify({"message": "User registered successfully!"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    Username = data["Username"]
    Password = data["Password"]

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT Password FROM users WHERE Username=?", (Username,))
    row = c.fetchone()
    conn.close()

    if row and row["Password"] == Password:
        return jsonify({"message": "Login successful!"})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

if __name__ == "__main__":
    app.run(debug=True)

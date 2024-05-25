from flask import Flask, jsonify, request
import sqlite3

app = Flask(__name__)

# Endpoint to get all users
@app.route('/users', methods=['GET'])
def get_users():
    try:
        conn = sqlite3.connect("volumes/users.sqlite")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user")
        users = cursor.fetchall()
        conn.close()
        return jsonify(users), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint to create a new user
@app.route('/users', methods=['POST'])
def create_user():
    try:
        new_user = request.json
        conn = sqlite3.connect("volumes/users.sqlite")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user (Name, GitHubID, Classes, KasmServerNeeded) VALUES (?, ?, ?, ?)",
                       (new_user['Name'], new_user['GitHubID'], str(new_user['Classes']), new_user['KasmServerNeeded']))
        conn.commit()
        conn.close()
        return jsonify({"message": "User created successfully", "user": new_user}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint to delete a user by ID
@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        conn = sqlite3.connect("volumes/users.sqlite")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)

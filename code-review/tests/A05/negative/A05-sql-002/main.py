import sqlite3


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def main():
    user_id = input("user id: ")
    print(get_user(user_id))


if __name__ == "__main__":
    main()

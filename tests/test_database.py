from storage.database import Database
from entities.user import User

db = Database()

user = User(
    user_id="vickey",
    password="123456"
)

db.add_user(user)

assert db.user_exists("vickey")

loaded = db.get_user("vickey")

print("=" * 60)
print("DATABASE TEST")
print("=" * 60)

print("User ID :", loaded.user_id)

print("Registered :", loaded.registered)

print()

print("Database Working Successfully")
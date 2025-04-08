from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": pwd_context.hash("secret"),
        "admin": True
    },
    "janedoe": {
        "username": "janedoe",
        "full_name": "Jane Doe",
        "email": "janedoe@example.com",
        "hashed_password": pwd_context.hash("password123"),
        "admin": False
    },
}

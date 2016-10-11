import os
import json
from jose import jwt

JWT_ALGORITHM="HS256"
JWT_SECRET = "secret"

# Use configured secret if available:
if "JWT_SECRET" in os.environ:
    JWT_SECRET = os.environ["JWT_SECRET"]
    print("Info: using configured secret")
else:
    print("Warn: using default JWT secret.")


def encode(data):
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode(token):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def main():
    global JWT_SECRET
    data = {"key": "value"}
    print(json.dumps(data))
    token = encode(data)
    print(json.dumps(token))
    #JWT_SECRET="wrong"
    print(decode(token))

if __name__ == "__main__":
    main()



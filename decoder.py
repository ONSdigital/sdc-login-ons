from jose import jwt

def get_json(token):
    return jwt.decode(token, "", "HS256", options={"verify_signature": False})

if __name__ == '__main__':
    # Show we can decode a token without validating the signature, so that we can see the values sent back from the server:
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyZXNwb25kZW50X3VuaXRzIjpbeyJyZWZlcmVuY2UiOiJhYmMiLCJuYW1lIjoiTnVyc2luZyBMdGQuIiwicXVlc3Rpb25uYWlyZXMiOlt7Im5hbWUiOiJNb250aGx5IENvbW1vZGl0aWVzIElucXVpcnkifV19XSwicmVzcG9uZGVudF9pZCI6IjEyMyIsImVtYWlsIjoiYm9iQGV4YW1wbGUuY29tIn0.iR93PcoUs7uJ443062qT65BkteSCK2Oc8BfcwYOYGWg"
    decoded = get_json(token)
    print(decoded)

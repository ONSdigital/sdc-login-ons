from json import loads, dumps
from decoder import get_json
import unittest
from app import app
from app import recreate_database, create_users
from jwt import encode


ok = 200
unauthorized = 401


class ComponentTestCase(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        self.app = app.test_client()

    def tearDown(self):
        pass

    def get_login_token(self):
        response = self.app.post(
            "/login",
            data=dumps({"email": "nick.gravgaard@example.com", "password": "password"}),
            content_type="application/json")
        string = response.data.decode()
        json = loads(string)
        return json["token"]

    @staticmethod
    def get_invalid_token():
        return encode({"this": "is not a valid token."})

    def test_should_return_unauthorized_for_no_credentials(self):

        # Given
        # A request with no json message

        # When
        # We try to login with an account or access code
        response_login = self.app.post("/login")

        # Then
        # We should get an unauthorized status code
        self.assertEqual(response_login.status_code, unauthorized)

    def test_should_return_unauthorized_for_invalid_email(self):

        # Given
        # An invalid email address
        email = "notauser@example.com"

        # When
        # We try to authenticate with the email
        response = self.app.post("/login", data={"email": email})

        # Then
        # We should get an unauthorized response
        self.assertEqual(response.status_code, unauthorized)

    def test_should_return_token_for_valid_email(self):

        # Given
        # A valid email address
        email = "david.carboni@example.com"
        password = "password"

        # When
        # We try to authenticate with the email address
        response = self.app.post(
            "/login",
            data=dumps({"email": email, "password": password}),
            content_type="application/json")

        # Then
        # We should get a response containing "reporting_units" in the data and the updated token.
        self.assertEqual(response.status_code, ok)
        string = response.data.decode()
        json = loads(string)
        self.assertTrue("token" in json)
        self.assertTrue("user_id" in get_json(json["token"]))

    def test_should_return_profile_for_valid_token(self):

        # Given
        # A valid account login token
        token = self.get_login_token()

        # When
        # We try to get our profile
        response = self.app.get("/profile", headers={"token": token})

        # Then
        # We should get a response containing our name and email address.
        self.assertEqual(response.status_code, ok)
        string = response.data.decode()
        json = loads(string)
        self.assertTrue("name" in json)
        self.assertTrue("email" in json)

    def test_should_not_return_profile_for_invalid_token(self):

        # Given
        # A valid token for an access code, not a user account
        token = self.get_invalid_token()

        # When
        # We try to get our profile
        response = self.app.get("/profile", headers={"token": token})

        # Then
        # We should get a response containing our name and email address.
        self.assertNotEqual(response.status_code, ok)

    def test_should_update_profile_for_valid_token(self):

        # Given
        # A valid account login token and a new name
        token = self.get_login_token()
        name = "Lord Quiffle"

        # When
        # We set our profile
        response = self.app.post("/profile", headers={"token": token}, data=dumps({"name": name}),
                                 content_type="application/json")

        # Then
        # Our name should have changed.
        self.assertEqual(response.status_code, ok)
        response = self.app.get("/profile", headers={"token": token})
        string = response.data.decode()
        json = loads(string)
        self.assertTrue("name" in json)
        self.assertEqual(name, json["name"])

    def test_should_not_update_profile_without_valid_token(self):

        # Given
        # A valid token for an access code, not a user account
        token = self.get_invalid_token()
        name = "You Shall Not Pass"

        # When
        # We set our profile
        response = self.app.post("/profile", headers={"token": token}, data=dumps({"name": name}), content_type="application/json")

        # Then
        # Our name should have changed.
        self.assertNotEqual(response.status_code, ok)
        response = self.app.get("/profile", headers={"token": self.get_login_token()})
        string = response.data.decode()
        json = loads(string)
        self.assertTrue("name" in json)
        self.assertNotEqual(name, json["name"])


if __name__ == '__main__':

    # Create database
    print("creating database")
    recreate_database()
    print("creating users")
    create_users()
    print("End of setup")

    # Run tests
    unittest.main()


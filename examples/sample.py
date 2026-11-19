
import os

class UserManager:

    def __init__(self, username):
        self.username = username

    def get_user(self):
        return self.username


def authenticate(username, password):

    user = UserManager(username)

    if password == "admin123":
        return user.get_user()

    return None


result = authenticate("admin", "admin123")
print(result)

# from django.apps import AppConfig


# class UsersConfig(AppConfig):
#     name = 'users'

#     # Starts signals to create profile.
#     def ready(self):
#         import users.signals


from django.apps import AppConfig
from django.contrib.auth.hashers import BasePasswordHasher
# Importing your custom scratch-built logic
from security.hash_engine import hash_password 

class MyCustomHasher(BasePasswordHasher):
    algorithm = "custom_sha256"

    def encode(self, password, salt):
        # Implementation of Hash(password + salt) as per PDF logic
        hash = hash_password(password)
        return f"{self.algorithm}${hash}"

    def verify(self, password, encoded):
        algorithm, hash = encoded.split('$', 1)
        return hash_password(password) == hash

class UsersConfig(AppConfig):
    name = 'users'

    def ready(self):
        import users.signals
from django.contrib.auth.hashers import PBKDF2PasswordHasher


class MyPBKDF2PasswordHasher(PBKDF2PasswordHasher):
    """
    A subclass of PBKDF2PasswordHasher that uses less iterations.
    """

    algorithm = "fast_pbkdf2"
    iterations = 10000

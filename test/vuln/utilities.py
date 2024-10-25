import requests
import random
import string

JAVA_URI = "http://irc.local:1337/api"


def createUser(username=None, name = "John Doe", password="password1"):
    if username is None:
        username = randstring(10)
    return requests.post(JAVA_URI + "/users", json={"username":username, "password":password, "name":name})

def randstring(n):
    return ''.join(random.choices(string.ascii_letters, k=n))
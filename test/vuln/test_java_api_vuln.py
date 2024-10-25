import requests
from utilities import randstring, createUser
import psycopg2
from websockets.sync.client import connect
import json
import datetime

class TestJavaApi:
    URI = "http://irc.local:1337/api"

    def test_JAVA_EASY(self):
        """
        SQLi on login
        """
        username = "'\"/\\yeet"+ randstring(10)
        response = createUser(username=username, password=username)
        assert response.status_code == 201
        d = response.json()
        assert d.get("username") == username
        userId = d.get("userId")
        response = requests.post(f"{self.URI}/login", json={"username": username, "password":username})
        assert response.status_code == 200
        response = requests.get(f"{self.URI}/users/{userId}", cookies=response.cookies)
        assert response.status_code == 200
        assert response.json().get("username") == username

    def test_JAVA_EASY_B(self):
        """
        No authentication on update room endpoint.
        """
        response = createUser()
        roomName = randstring(10)
        response = requests.post(f"{self.URI}/rooms", json={"name":roomName}, cookies=response.cookies)
        victim_room = response.json().get("roomId")


        response = createUser()
        response = requests.put(f"{self.URI}/rooms/{victim_room}", json={"hostId":response.json()["userId"], "name":roomName}, cookies=response.cookies)
        assert response.status_code >= 300
        response = requests.get(f"{self.URI}/rooms/{victim_room}")
        assert response != 200
        assert "roomName" not in response.text
        

    def test_JAVA_MODERATE_A(self):
        """
        Can add a user to any room
        """
        # create a room as victim
        response = createUser()
        response = requests.post(f"{self.URI}/rooms", json={"name":randstring(10)}, cookies=response.cookies)
        victim_room = response.json().get("roomId")

        # attacker user
        response = createUser()
        attacker = response.json().get("username")
        cookies = response.cookies
        response = requests.post(f"{self.URI}/rooms", json={"name":randstring(10)}, cookies=cookies)
        room = response.json().get("roomId")

        # victim room id goes in body
        response = requests.post(f"{self.URI}/rooms/{room}/users", cookies=cookies, json={"username":attacker, "roomId":victim_room})
        response = requests.get(f"{self.URI}/rooms/{victim_room}/users", cookies=cookies)
        assert response.status_code != 200
        assert attacker not in response.text


    def test_JAVA_MODERATE_B(self):
        """
        Can see password hash for all users I have access to
        """
        # create a room as victim
        response = createUser()
        cookies = response.cookies
        response = requests.post(f"{self.URI}/rooms", json={"name":randstring(10)}, cookies=cookies)
        room = response.json().get("roomId")
        response = createUser()
        victim = response.json()
        response = requests.post(f"{self.URI}/rooms/{room}/users", cookies=cookies, json={"username":victim.get("username"), "roomId":room})
        assert response.json().get("password", False) is False
        assert requests.get(f"{self.URI}/users/{victim.get("userId")}", cookies=cookies).json().get("password", "") == ""


    def test_JAVA_MODERATE_C(self):
        """
        CORS is wide open
        """
        response = createUser()
        userId = response.json().get("userId")
        cookies = response.cookies
        response = requests.options(f"{self.URI}/users/{userId}", headers={"Origin": "http://localhost.evil.com", "sec-fetch-mode": "cors", "access-control-request-method":"GET"}, cookies=cookies)
        assert response.headers.get("Access-Control-Allow-Credentials", "") != "true"

        response = requests.options(f"{self.URI}/users/{userId}", headers={"Origin": "http://irc.local:1337", "sec-fetch-mode": "cors", "access-control-request-method":"GET"}, cookies=cookies)
        assert response.headers.get("Access-Control-Allow-Credentials", "") == "true"


    def test_JAVA_HARD(self):
        """
        Can reuse room token as auth token for user with the same ID as my room (and vice versa, though not tested for specifically, hopefully you've fixed both)
        """

        userAndRoomId = 10000

        response = createUser()
        attackerId = response.json().get("userId")
        attackerCookies = response.cookies

        conn = psycopg2.connect(database="postgres",
                                host="postgresql",
                                user="postgres",
                                password="password",
                                port="5432")
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM rooms WHERE id={userAndRoomId};")
        conn.commit()
        cursor.execute(f"INSERT INTO rooms(id, name, host) OVERRIDING SYSTEM VALUE VALUES({userAndRoomId}, 'myroom', {attackerId}) RETURNING id;")
        conn.commit()
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM users WHERE id={userAndRoomId};")
        conn.commit()
        cursor.execute(f"INSERT INTO users(id, username, name, password_hash) OVERRIDING SYSTEM VALUE VALUES({userAndRoomId}, 'victim', 'victim', '$2a$10$Vo37d.WM595BpbovmaE7WupvHUOx7mgH1IZCAnivvh.62ej.3vxxy') RETURNING id;")
        conn.commit()


        victimToken = requests.get(f"{self.URI}/connect/{userAndRoomId}", cookies=attackerCookies).text

        response = requests.get(f"{self.URI}/users/{userAndRoomId}", cookies={"auth": victimToken})
        
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM rooms WHERE id={userAndRoomId};")
        conn.commit()
        cursor.execute(f"DELETE FROM users WHERE id={userAndRoomId};")
        conn.commit()
        assert response.status_code != 200
        assert 'victim' not in response.text
        


    def test_JAVA_INSANE(self):
        """
        Can break room user limits by abuse race conditions
        """
        import asyncio
        import httpx

        response = createUser()
        cookies = response.cookies
        response = requests.post(f"{self.URI}/rooms", json={"name":randstring(10)}, cookies=cookies)
        room = response.json().get("roomId")


        users = []
        for i in range(20):
            response = createUser()
            users.append(response.json()['username'])
    
        async def add_user_to_room(client, user):
            await client.post(f"{self.URI}/rooms/{room}/users", cookies=cookies, json={"username":user, "roomId":room})


        async def main():
            async with httpx.AsyncClient() as client:
                tasks = []
                for user in users:
                    tasks.append(asyncio.ensure_future(add_user_to_room(client, user)))
                
                # Get responses
                await asyncio.gather(*tasks, return_exceptions=True)
                
                
                # Async2sync sleep
                await asyncio.sleep(0.5)
                response = requests.get(f"{self.URI}/rooms/{room}/users", cookies=cookies)
                data = response.json()
                assert len(data) <= 6


        asyncio.run(main())




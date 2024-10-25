import requests
import utilities
from websockets.sync.client import connect
from websocket import WebSocketTimeoutException
import json
import datetime
import time

"""
This one needs to be the last test suite because it does DoS
"""



def wait_for_message(ws, timeout=5):
    start = time.time()
    while time.time() - start < timeout:
        try:
            message = ws.recv()
            return message
        except WebSocketTimeoutException:
            time.sleep(0.1)
    raise TimeoutError("Message not received in time")

class TestNodeWebsocket:
    JAVA_API = "http://irc.local:1337/api"
    WEBSOCKET = "ws://irc.local:1337/ws"


    def test_JS_EASY(self):
        # user 1
        response = utilities.createUser()
        cookies1 = response.cookies
        user1 = response.json()
        response = requests.post(
            f"{self.JAVA_API}/rooms",
            json={"name": "roomba"},
            cookies=cookies1,
        )
        roomId = response.json().get("roomId")
        token1 = requests.get(
            f"{self.JAVA_API}/connect/{roomId}", cookies=cookies1
        ).text

        ws1 = connect(
            f"{self.WEBSOCKET}/?user={user1.get("userId")}&token={token1}",
            additional_headers={"Cookie": "auth=" + cookies1.get("auth"), "Origin":"http://irc.local"}
        )
        ws1.send(f"JSON.parse('{json.dumps(
                {
                    "text": "injected",
                    "timestamp": datetime.datetime.now().timestamp(),
                }
            )}')")
        txt = None
        try:
            message1 = wait_for_message(ws1)
            txt = json.loads(message1)[0]["text"]
        except:
            assert True
        assert txt != "injected"


    def test_JS_MODERATE_A(self):
        """
        NoSQL injection
        """
        # user 1
        response = utilities.createUser()
        cookies1 = response.cookies
        user1 = response.json()
        response = requests.post(
            f"{self.JAVA_API}/rooms",
            json={"name": "roomba"},
            cookies=cookies1,
        )
        roomId = response.json().get("roomId")
        token1 = requests.get(
            f"{self.JAVA_API}/connect/{roomId}", cookies=cookies1
        ).text

        ws1 = connect(
            f"{self.WEBSOCKET}/?user={user1.get("userId")}&token={token1}",
            additional_headers={"Cookie": "auth=" + cookies1.get("auth"), "Origin":"http://irc.local"}
        )
        ws1.send(
            json.dumps(
                {
                    "text": "what up!",
                    "timestamp": datetime.datetime.now().timestamp(),
                }
            )
        )

        response = utilities.createUser()
        cookies2 = response.cookies
        user2 = response.json()
        response = requests.post(
            f"{self.JAVA_API}/rooms",
            json={"name": "roomba"},
            cookies=cookies2,
        )
        roomId2 = response.json().get("roomId")
        token2 = requests.get(
            f"{self.JAVA_API}/connect/{roomId2}", cookies=cookies2
        ).text

        nosqli = '2,"filter":{"room":"' + str(roomId) + '"}'
        ws2 = connect(
            f"{self.WEBSOCKET}/?user={user2.get("userId")}&token={token2}&count={nosqli}",
            additional_headers={"Cookie": "auth=" + cookies2.get("auth"), "Origin":"http://irc.local"}
        )
        msgs = wait_for_message(ws2)
        msgs = json.loads(msgs)
        for msg in msgs:
            assert msg["text"] != "what up!"
        else:
            assert True

    def test_JS_MODERATE_B(self):
        """
        Can impresonate users/rooms by adding room / user ID to their message
        """

        # user 1
        response = utilities.createUser()
        cookies1 = response.cookies
        user1 = response.json()
        response = requests.post(
            f"{self.JAVA_API}/rooms",
            json={"name": "roomba"},
            cookies=cookies1,
        )
        roomId1 = response.json().get("roomId")
        token1 = requests.get(
            f"{self.JAVA_API}/connect/{roomId1}", cookies=cookies1
        ).text

        # user 2
        response = utilities.createUser()
        cookies2 = response.cookies
        user2 = response.json()
        response = requests.post(
            f"{self.JAVA_API}/rooms",
            json={"name": "roomba2"},
            cookies=cookies2,
        )
        roomId2 = response.json().get("roomId")

        token2 = requests.get(
            f"{self.JAVA_API}/connect/{roomId2}", cookies=cookies2
        ).text

        ws1 = connect(
            f"{self.WEBSOCKET}/?user={user1.get("userId")}&token={token1}",
            additional_headers={"Cookie": "auth=" + cookies1.get("auth"), "Origin":"http://irc.local"}
        )
        try:
            ws2 = connect(
                    f"{self.WEBSOCKET}/?user={user2.get("userId")}&token={token2}",
                    additional_headers={"Cookie": "auth=" + cookies2.get("auth"), "Origin":"http://irc.local"}
            )
            ws2.send(
                json.dumps(
                    {
                        "text": "hello world!",
                        "timestamp": datetime.datetime.now().timestamp(),
                        "userId": user1.get("userId"),
                        "room": str(roomId1),
                    }
                )
            )
            message1 = wait_for_message(ws1)
            msg1 = json.loads(message1)[0]
            txt = msg1["text"]
        except:
            # something went wrong with the connection
            assert True
            return

        assert txt != "hello world!"

    def test_JS_HARD(self):
        """
        Prototype pollution.
        Should be last because of DoS.
        """

        # user 2
        response = utilities.createUser()
        cookies1 = response.cookies
        user1 = response.json()
        response = requests.post(
            f"{self.JAVA_API}/rooms",
            json={"name": "roomba"},
            cookies=cookies1,
        )
        roomId1 = response.json().get("roomId")
        token1 = requests.get(
            f"{self.JAVA_API}/connect/{roomId1}", cookies=cookies1
        ).text

        ws1 = connect(
            f"{self.WEBSOCKET}/?user={user1.get("userId")}&token={token1}",
            additional_headers={"Cookie": "auth=" + cookies1.get("auth"), "Origin":"http://irc.local"}
        )
        ws1.send(
            json.dumps(
                {
                    "text": "dos",
                    "timestamp": datetime.datetime.now().timestamp(),
                    "__proto__": {"toString": 1},
                }
            )
        )

        try:
            time.sleep(2)
            ws1 = connect(
                f"{self.WEBSOCKET}/?user={user1.get("userId")}&token={token1}",
                additional_headers={"Cookie": "auth=" + cookies1.get("auth"), "Origin":"http://irc.local"}
            )
            ws1.send(
                json.dumps(
                    {
                        "text": "hi",
                        "timestamp": datetime.datetime.now().timestamp(),
                    }
                )
            )
            message1 = ws1.recv()
            msg1 = json.loads(message1)[0]
            assert msg1["text"] == "hi"

        except:
            # Server crash because of toString override
            assert False

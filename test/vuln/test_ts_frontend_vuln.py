import datetime
import json
import requests
import utilities
from websockets.sync.client import connect
from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from websocket import WebSocketTimeoutException
import time

def wait_for_message(ws, timeout=5):
    start = time.time()
    while time.time() - start < timeout:
        try:
            message = ws.recv()
            return message
        except WebSocketTimeoutException:
            time.sleep(0.1)
    raise TimeoutError("Message not received in time")

def get_driver():
    """Sets chrome options for Selenium.
    Chrome options for headless browser is enabled.
    See https://nander.cc/using-selenium-within-a-docker-container
    """
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-software-rasterizer")
    chrome_options.add_argument("--disable-dev-shm-usage")
    #chrome_options.add_argument("--disable-background-timer-throttling")
    #chrome_options.add_argument("--disable-backgrounding-occluded-windows")
    #chrome_options.add_argument("--disable-renderer-backgrounding")
    chrome_options.set_capability("goog:loggingPrefs", {'browser': 'ALL'})
    service = ChromeService(executable_path="/usr/bin/chromedriver")
    # chrome_options.experimental_options["prefs"] = chrome_prefs
    # chrome_prefs["profile.default_content_settings"] = {"images": 2}
    return webdriver.Chrome(options=chrome_options, service=service)

class TestIrcFrontendVuln:

    URL = "http://irc.local:1337"


    def test_TS_MODERATE(self):
        """
        XSS in fileLocation
        """

        # user 2
        response = utilities.createUser()
        user1 = response.json()
        cookies1 = response.cookies
        response = requests.post(
            f"{self.URL}/api/rooms",
            json={"name": "roomba"},
            cookies=cookies1,
        )
        roomId = response.json().get("roomId")

        token1 = requests.get(
            f"{self.URL}/api/connect/{roomId}", cookies=cookies1
        ).text

        ws1 = connect(
            f"ws://irc.local:1337/ws?user={user1.get("userId")}&token={token1}",
            additional_headers={"Cookie": "auth=" + cookies1.get("auth"), "Origin":"http://irc.local"}
        )
        ws1.send(
            json.dumps(
                {
                    "text": "hello world!",
                    "timestamp": datetime.datetime.now().timestamp(),
                    "fileName": "MyFileName",
                    "fileLocation": "javascript://%0aalert(1)",
                }
            )
        )
        wait_for_message(ws1)
        
        driver = get_driver()
        driver.implicitly_wait(2)
        driver.get(self.URL + "/login")
        driver.add_cookie({"name":"auth", "value":cookies1.get("auth")})
        driver.get(self.URL + "/")

        driver.find_element(By.XPATH, f"//span[@id='room-{roomId}']").click()
        driver.find_element(By.XPATH, "//a[contains(text(), 'MyFileName')]").click()

            
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present(),
                                           'timeout')
            alert = driver.switch_to.alert
            alert.accept()
            assert False
        except TimeoutException:
            assert True
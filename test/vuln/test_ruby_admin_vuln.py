import requests
import utilities as utils
import psycopg2
from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import time

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


class TestRubyAdmin:
    URI = "http://irc.local:1337/admin"

    def test_RUBY_EASY_A(self):
        # SQLi on login (given valid username/password)

        # create admin with sqli username
        username = "'\"/\\yeet"+ utils.randstring(10)
        response = utils.createUser(username=username)
        id = response.json()['userId']
        conn = psycopg2.connect(database="postgres",
                                host="postgresql",
                                user="postgres",
                                password="password",
                                port="5432")
        cursor = conn.cursor()
        cursor.execute(f"UPDATE users SET role='admin' WHERE id={id};")
        conn.commit()

        # check that admin can login
        response = requests.post(f"{self.URI}/login", data={"username":username, "password":"password1"}, allow_redirects=False)
        admin_cookies = response.cookies
        assert 400 > response.status_code >= 200

        # check that the admin can do admin things, which is proof of login
        response = requests.get(f"{self.URI}/dashboard", cookies=response.cookies)
        assert "User Dashboard" in response.text
        response = utils.createUser()
        uname = response.json()["username"]
        user_to_ban = response.json()['userId']
        response = requests.post(f"{self.URI}/ban", json={"userId":user_to_ban}, cookies = admin_cookies)
        response = requests.post("http://irc.local:1337/api/login", json={"username":uname, "password":"password1"})
        assert response.status_code >= 400

    def test_RUBY_EASY_B(self):
        # Forced browsing / improper auth (no auth on dashboard)
        response = requests.get(f"{self.URI}/dashboard")
        assert "User Dashboard" not in response.text

        
    def test_RUBY_EASY_C(self):
        # hardcoded credentials
        response = requests.post(f"{self.URI}/login", data={"username":"admin", "password":"admin"}, allow_redirects=False)
        admin_cookies = response.cookies

        # check that the admin can do admin things, which is proof of login
        response = requests.get(f"{self.URI}/dashboard", cookies=response.cookies)
        response = utils.createUser()
        uname = response.json()["username"]
        user_to_ban = response.json()['userId']
        response = requests.post(f"{self.URI}/ban", json={"userId":user_to_ban}, cookies = admin_cookies)
        response = requests.post("http://irc.local:1337/api/login", json={"username":uname, "password":"password1"})
        assert not response.status_code >= 400

    def test_RUBY_EASY_D(self):
        # reflected XSS
        driver = get_driver()
        driver.implicitly_wait(2)
        driver.get(self.URI + "/login?error=<script>alert(1)</script>")

        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present(),
                                           'timeout')
            alert = driver.switch_to.alert
            alert.accept()
            assert False
        except TimeoutException:
            assert True

    def test_RUBY_MODERATE(self):
        # second-order/stored xss

        response = utils.createUser(username="<script>alert(1)</script>" + utils.randstring(10))


        username = utils.randstring(10)
        response = utils.createUser(username=username)
        id = response.json()['userId']
        conn = psycopg2.connect(database="postgres",
                                host="postgresql",
                                user="postgres",
                                password="password",
                                port="5432")
        cursor = conn.cursor()
        cursor.execute(f"UPDATE users SET role='admin' WHERE id={id};")
        conn.commit()

        response = requests.post(f"{self.URI}/login", data={"username":username, "password":"password1"}, allow_redirects=False)
        cookies = response.cookies
        driver = get_driver()
        driver.implicitly_wait(2)
        driver.get(self.URI + "/login")
        driver.add_cookie({"name":"rack.session", "value":cookies.get("rack.session")})
        driver.get(self.URI + "/dashboard")

        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present(),
                                           'timeout')
            alert = driver.switch_to.alert
            alert.accept()
            assert False
        except TimeoutException:
            assert True
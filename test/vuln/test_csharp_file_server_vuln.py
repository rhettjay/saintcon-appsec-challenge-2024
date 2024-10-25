import requests
from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

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

class TestCSharpFileServerVuln:

    URL = "http://irc.local:1337/files"

    def test_CS_EASY(self):
        filename = "../../../../../../../../../etc/passwd"
        response = requests.get(self.URL + "/?path=" + filename)
        assert "root" not in response.text

    def test_CS_MODERATE(self):
        file_content = "second note"
        files = {'file': file_content}
        response = requests.post(self.URL + "/upload", files=files, data={"filename":"....//....//....//....//....//....//....//tmp/exploit.txt"})
        if 200 <= response.status_code < 300:
            filename = response.text
            response = requests.get(self.URL + "/?path=" + filename)
            assert response.text == file_content
        else:
            #it's fine to block uploads with traversal in the name
            assert True


    def test_CS_HARD(self):


        """
        An attacker can upload an SVG file with Javascript and it will be returned
        read.
        """
        file_content = """<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
   <use href="data:image/svg+xml,&lt;svg id='x' xmlns='http://www.w3.org/2000/svg'&gt;&lt;image href='1' onerror='eval(atob(location.hash.slice(1)))' /&gt;&lt;/svg&gt;#x" />
   <script>alert(1)</script>
</svg>
        """
        data = {'filename': "xss.svg"}
        response = requests.post(self.URL + "/upload", data=data, files={"file":file_content})
        driver = get_driver()
        driver.implicitly_wait(2)
        import time
        time.sleep(2)
        try:
            driver.get(f"{self.URL}/?path=xss.svg#YWxlcnQoJ2hlbGxvJykK")
            WebDriverWait(driver, 1).until(EC.alert_is_present(),
                                           'timeout')
            alert = driver.switch_to.alert
            alert.accept()
            assert False
        except TimeoutException:
            assert True

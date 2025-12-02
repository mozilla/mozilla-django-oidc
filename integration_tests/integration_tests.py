import unittest

from selenium.webdriver.firefox.service import Service
from splinter import Browser, Config


class IntegrationTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(IntegrationTest, self).__init__(*args, **kwargs)

        self.webdriver = "firefox"
        self.account = {
            "username": "example_username",
            "password": "example_p@ssw0rd",
            "email": "example@example.com",
        }
        self.config = Config(headless=True)
        self.service = Service(executable_path="/usr/bin/geckodriver")

    def setUp(self):
        """Create test account in `testprovider` instance"""
        with Browser(
            self.webdriver, config=self.config, service=self.service
        ) as browser:
            browser.visit("http://testprovider:8080/account/signup")
            browser.find_by_css("#id_username").fill(self.account["username"])
            browser.find_by_css("#id_password").fill(self.account["password"])
            browser.find_by_css("#id_password_confirm").fill(self.account["password"])
            browser.find_by_css("#id_email").fill(self.account["email"])
            browser.find_by_css(".btn-primary").click()

    def tearDown(self):
        """Remove test account from `testprovider` instance"""
        with Browser(
            self.webdriver, config=self.config, service=self.service
        ) as browser:
            self.perform_login(browser)
            browser.visit("http://testprovider:8080/account/delete")
            browser.find_by_css(".btn-danger").click()

    def perform_login(self, browser):
        """Perform login using webdriver"""
        browser.visit("http://testrp:8081")
        browser.find_by_css("div > a").click()
        browser.find_by_css("#id_username").fill(self.account["username"])
        browser.find_by_css("#id_password").fill(self.account["password"])
        browser.find_by_css(".btn-primary").click()

    def perform_logout(self, browser):
        """Perform logout using webdriver"""
        browser.visit("http://testrp:8081")
        browser.find_by_css('input[value="Logout"]').click()

    def test_login(self):
        """Test logging in `testrp` using OIDC"""
        with Browser(
            self.webdriver, config=self.config, service=self.service
        ) as browser:
            # Check that user is not logged in
            browser.visit("http://testrp:8081")
            self.assertTrue(browser.is_text_not_present("Current user:"))

            # Perform login
            self.perform_login(browser)

            # Accept scope
            browser.find_by_css('input[name="allow"]').click()

            # Check that user is now logged in
            self.assertTrue(browser.is_text_present("Current user:"))

    def test_logout(self):
        """Test logout functionality of OIDC lib"""
        with Browser(
            self.webdriver, config=self.config, service=self.service
        ) as browser:
            # Check that user is not logged in
            browser.visit("http://testrp:8081")
            self.assertTrue(browser.is_text_not_present("Current user:"))

            self.perform_login(browser)

            # Accept scope
            browser.find_by_css('input[name="allow"]').click()

            # Check that user is now logged in
            self.assertTrue(browser.is_text_present("Current user:"))

            self.perform_logout(browser)

            # Check that user is now logged out
            self.assertTrue(browser.is_text_not_present("Current user:"))


if __name__ == "__main__":
    unittest.main()

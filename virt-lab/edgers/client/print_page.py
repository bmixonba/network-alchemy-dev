#!/usr/bin/env python3

from selenium import webdriver
import sys, time
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

def get_clear_dns_cache_button(driver):
    return driver.find_element_by_css_selector('#clearDNSCache')

def clear_fixefox_dnscache(driver, timeout=10):
    """ """
    driver.get("about:networking#dns")
    print("Here, 1")
    wait = WebDriverWait(driver, timeout)
    print("Here, 2")
    wait.until(get_clear_dns_cache_button)
    print("Here, 3")
    get_clear_dns_cache_button(driver).click()
    print("Here, 4")


def main():
    url = 'http://www.fartbook.com'
    if len(sys.argv) > 1:
        url = sys.argv[1]
    try:
        fireFoxOptions = webdriver.FirefoxOptions()
        fireFoxOptions.set_headless()
        ff = webdriver.Firefox(firefox_options=fireFoxOptions)
        clear_fixefox_dnscache(ff, timeout=60)
        ff.get("https://www.breakpointingbad.com")
        ready = input("Hit enter to continue")

        ff.get(url)
        print(ff.page_source)
    finally:
        try:
            ff.close()
        except:
            pass

if __name__ == '__main__':
    main()

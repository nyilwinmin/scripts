#!/usr/bin/env python3
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from datetime import date, datetime
import time
import boto3
import requests
from datetime import datetime, timedelta, timezone
import random
import string

def generate_random_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(length))

# Example usage: Generate a random string of length 10
random_string = generate_random_string(10)


##################### SELENIUM #########################
options = webdriver.ChromeOptions()

# CHANGE THIS TO YOUR CHROME PROFILE DIRECTORY
options.add_argument(r'--user-data-dir=C:\Users\nyilwinmin\AppData\Local\Google\Chrome\User Data\Default')
options.add_argument('--profile-directory=Default')

# CHANGE THIS TO THE PATH OF chromedriver.exe
service = Service(executable_path="C:/Users/nyilwinmin/Desktop/chromedriver.exe")

driver = webdriver.Chrome(service=service, options=options)
driver.implicitly_wait(45)

driver.get("https://web.whatsapp.com/")
time.sleep(30)

# Wait until the element is located
# wait = WebDriverWait(driver, 30)
# findchat = wait.until(EC.presence_of_element_located((By.XPATH, "//span[@title='ME']")))

findchat = driver.find_element(By.XPATH, "//span[@title='ME']")
# findchat = driver.find_element(By.XPATH, "//span[@title='[Internal] SSNet Matters']")
findchat.click()

messagebox = driver.find_element(By.XPATH, "/html/body/div[1]/div/div[2]/div[4]/div/footer/div[1]/div/span[2]/div/div[2]/div[1]/div/div[1]/p")
messagebox.send_keys(random_string)
messagebox.send_keys(Keys.RETURN)
time.sleep(5)
driver.quit()
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from contracts.models import User
import sys, time

def get_contract_manager_password():
    try:
        contract_manager = User.objects.get(username="contract_manager")
        return contract_manager.password
    except User.DoesNotExist:
        raise ValueError("Contract Manager user does not exist in the database")

def startChromiumBot(url):
    print(url, file=sys.stdout)
    chrome_options = Options()
    chrome_options.binary_location = "/usr/bin/chromium-browser" 
    chrome_options.add_argument("--headless") 
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-software-rasterizer")
    
    chrome_service = Service("/usr/bin/chromedriver")
    driver = webdriver.Chrome(service=chrome_service, options=chrome_options)

    try:
        driver.get('http://127.0.0.1:1337/login')
        
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.ID, "loginBtn"))
        )
        
        username = "contract_manager"
        password = get_contract_manager_password()
        
        input1 = driver.find_element(By.XPATH, '/html/body/code/section/div/div/div/form/div[1]/input')
        input2 = driver.find_element(By.XPATH, '/html/body/code/section/div/div/div/form/div[2]/input')
        
        input1.send_keys(username)
        input2.send_keys(password)
        
        submit_button = driver.find_element(By.ID, "loginBtn")
        driver.execute_script("arguments[0].click();", submit_button)

        driver.get(url)
        time.sleep(30)
    finally:
        driver.quit()

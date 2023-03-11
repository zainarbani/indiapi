import argparse
import json
import os
import sys
from indihome import AESCipher, APISec, ApiEndpoint


def genTok():
    if os.path.isfile("token.txt"):
        with open("token.txt", "r") as f:
            rtok = f.read()
        r = ApiEndpoint().refreshToken(rtok)
        if r["ok"]:
            return r["data"]["token"]
        else:
            sys.exit(r["message"])
    else:
        sys.exit("Please login to your account")


def doLogin(dat):
    chk = ApiEndpoint().chkUser(dat[0])
    dcr = AESCipher().decrypt(chk["data"])
    chk["data"] = json.loads(dcr)
    if chk["ok"]:
        em = chk["data"]["email"]
        dlg = ApiEndpoint().apiLogin(em, dat[1])
        if dlg["ok"]:
            if dlg["data"]["twoFactorAuth"]:
                print("2FA Enabled")
                pn = dlg["data"]["mobile"]
                sot = ApiEndpoint().sendOtp(em, pn)
                if sot["ok"]:
                    print(sot["message"])
                    vot = ApiEndpoint().verifyOtp(em, dat[1], pn)
                    if vot["ok"]:
                        print(vot["message"])
                        rtok = vot["data"]["refreshToken"]
                        with open("token.txt", "w") as f:
                            f.write(rtok)
                        print("Login Success, Token saved to token.txt")
                    else:
                        sys.exit(vot["message"])
                else:
                    sys.exit(sot["message"])
        else:
            sys.exit(dlg["message"])
    else:
        sys.exit(chk["message"])


def getFup(dat):
    tok = genTok()
    r = ApiEndpoint().getUsage(dat[0], tok)
    if r["ok"]:
        rq = r["data"]["dataUsage"]["usage"]["remainingQuota"]
        uq = r["data"]["dataUsage"]["usage"]["usedQuata"]  # typo at its best
        by = r["data"]["dataUsage"]["usage"]["unit"]
        msg = f"\nRemaining Quota: {rq} {by}\nUsed Quota: {uq} {by}"
        print(msg)
    else:
        sys.exit(r["message"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IndiHome")
    parser.add_argument("--login", nargs=2, metavar=("[email/phone]", "[password]"))
    parser.add_argument("--fup", nargs=1, metavar=("[internet number]"))
    args = parser.parse_args()
    if args.login:
        doLogin(args.login)
    elif args.fup:
        getFup(args.fup)
    else:
        parser.print_help()
        sys.exit()

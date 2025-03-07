#!/usr/bin/env python3

import xled
import time

import requests
import time
import json
import dbm

import logging
import logging.handlers
import unicodedata
import typing
import yaml
import matplotlib


class NATemps(typing.Dict):
    pass


class Color(typing.Dict):
    red: int
    green: int
    blue: int


class Config(typing.TypedDict):
    nadevice: str


class NAtoken(typing.TypedDict):
    expire_at: float
    expire_in: float
    access_token: str


Database: typing.TypeAlias = "dbm._Database"


defaults: Config = {
    "nadevice": "källaren",
}

logger = logging.getLogger()


def get_netatmo_token(db: Database) -> NAtoken:
    key = "natoken"

    natoken: typing.Optional[NAtoken] = None
    if key in db:
        natoken = json.loads(db[key])

    if natoken and natoken["expire_at"] > time.time():
        return natoken

    with open("config.yaml") as f:
        naconfig = yaml.safe_load(f)

    t = time.time()

    configtoken = naconfig["refreshtoken"]
    refreshtoken = configtoken

    if b"narefreshtoken" in db.keys():
        dbtoken = db["narefreshtoken"]

        if not isinstance(dbtoken, bytes):
            dbtoken = dbtoken.encode("ascii")

        old, new = dbtoken.split(b"\x00")

        if old == refreshtoken.encode("ascii"):
            refreshtoken = new.decode()

    d = {
        "grant_type": "refresh_token",
        "refresh_token": refreshtoken,
        "client_id": naconfig["clientid"],
        "client_secret": naconfig["clientsecret"],
    }

    r = requests.request(
        method="POST",
        url="https://api.netatmo.com/oauth2/token",
        headers={
            "Content-type": "application/x-www-form-urlencoded",
        },
        data=d,
    )

    if not r.ok:
        raise SystemError("Failed to refresh token")

    token = r.json()

    db[b"narefreshtoken"] = (
        configtoken.encode("ascii") + b"\x00" + token["refresh_token"].encode("ascii")
    )

    token["expire_at"] = t + token["expire_in"]

    db[key] = json.dumps(token)
    return typing.cast(NAtoken, token)


def get_netatmo_temps(db: Database) -> NATemps:
    """Returns data from netatmo, note that data may not be provided or may be
    out of date.
    """
    key = "natemps"
    t = time.time()
    natemps: NATemps = NATemps()
    if key in db:
        natemps = json.loads(db[key])

    if natemps and (natemps["last_store"] + 10 * 60) > t:
        # We have recent data
        return natemps

    token = get_netatmo_token(db)
    r = requests.request(
        method="GET",
        url="https://api.netatmo.com/api/getstationsdata",
        headers={"Authorization": f"Bearer {token['access_token']}"},
    )

    if not r.ok:
        # On error, we don't fail but rather do not return any data
        return NATemps()

    # Only consider one device for now

    for nadata in r.json()["body"]["devices"]:

        fill_netatmo_module_data(nadata, natemps)

        for p in nadata["modules"]:
            fill_netatmo_module_data(p, natemps)

    for p in list(natemps.keys()):
        normalkey = unicodedata.normalize("NFC", p)
        if p != normalkey:
            natemps[normalkey] = natemps[p]

    db[key] = json.dumps(natemps)

    return natemps


def fill_netatmo_module_data(na: typing.Dict, t: NATemps) -> None:
    "Fill in temperature from netatmo details"

    name = "device"
    if "module_name" in na:
        name = na["module_name"]

    if not "dashboard_data" in na:
        return

    if "Temperature" in na["dashboard_data"]:
        t[name] = {
            "temperature": na["dashboard_data"]["Temperature"],
            "time": na["dashboard_data"]["time_utc"],
        }
        t["last_store"] = time.time()


def setup_logger(
    console_level: int = logging.DEBUG,
    file_level: int = logging.DEBUG,
    filename: str = "twinkletemp.log",
) -> None:
    h = logging.StreamHandler()
    h.setLevel(console_level)
    logger.addHandler(h)
    f = logging.handlers.TimedRotatingFileHandler(
        filename, when="midnight", backupCount=30
    )
    f.setFormatter(logging.Formatter("{asctime} - {levelname} - {message}", style="{"))
    f.setLevel(file_level)
    logger.addHandler(f)

    logger.setLevel(min(file_level, console_level))


def get_device_name() -> str | None:
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
        if "showname" in config:
            return config["showname"]
    return None


def set_color(c: Color, db: Database) -> None:
    if "led" in db:
        indb = db["led"].decode("ascii").split(",")
        ip = str(indb[0])
        hw = str(indb[1])
    else:
        leds = xled.discover.discover()
        ip = str(leds.ip_address)
        hw = str(leds.hw_address)
        todb = f"{ip},{hw}"
        db["led"] = todb

    control = xled.ControlInterface(ip, hw)

    control.set_led_color_rgb(c["red"], c["green"], c["blue"])


# Turn
def color_from_temp(temp: float, cm) -> Color:

    if temp < -20:
        c = 0
    elif temp > 30:
        c = 1
    else:
        c = (temp + 20) / 50
    col = cm(c, bytes=True)

    return Color(red=int(col[0]), green=int(col[1]), blue=int(col[2]))


if __name__ == "__main__":
    setup_logger()

    dev = get_device_name()
    if not dev:
        logger.error("No device to show, please set showname in config")
        raise SystemError

    db = dbm.open("twinkletemp.db", "c")

    temp = get_netatmo_temps(db)[dev]

    cm = matplotlib.colormaps["rainbow"]
    col = color_from_temp(temp["temperature"], cm)
    set_color(col, db)

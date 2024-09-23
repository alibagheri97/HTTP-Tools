import socket
import requests
from bs4 import BeautifulSoup


class My_IP:
    def __init__(self):
        """
        Access to the Data with self.data_info

        """
        self.data_info = {}

        self.site_get = requests.get("https://ipnumberia.com/")
        if self.site_get.status_code == 200:
            self.bs = BeautifulSoup(self.site_get.text, "html.parser")
            self.bs = self.bs.body
            self.section_list = list(self.bs.section)
            info_list = self.section_list[3].find_all("tr")

            key_translate = {"ای پی": "ip",
                             "ورژن ip": "ipv",
                             "سیستم عامل": "os",
                             "مرورگر": "browser",
                             "کشور": "country",
                             "استان": "state",
                             "شهر": "city",
                             }
            info = {}
            for i in info_list:
                try:
                    _title = i.find("div", {"class": "tooltip_style1"}).text.replace("\r", "").replace("\t",
                                                                                                       "").replace("\n",
                                                                                                                   "")
                    _value = i.find("td").text

                    if _title in key_translate:
                        _title = key_translate[_title]
                        info[_title] = _value
                    else:
                        continue
                except:
                    pass
            if info:
                self.data_info = info

    def get_ip(self):
        return self.data_info["ip"]

    def get_ip_version(self):
        """ 4 or 6 """
        return self.data_info["ipv"]

    def get_country(self):
        return self.data_info["country"].split(" ")[0]

    def get_state(self):
        return self.data_info["state"]

    def get_city(self):
        return self.data_info["city"]

    def get_os(self):
        return self.data_info["os"]

    def get_browser(self):
        return self.data_info["browser"]


def domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

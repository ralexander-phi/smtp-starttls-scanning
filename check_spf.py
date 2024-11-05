#!/usr/bin/env python

import dns.rdatatype
import dns.resolver
import requests
import sys

MY_DOMAIN = sys.argv[1]
print(MY_DOMAIN)

my_ip_address = requests.get("https://icanhazip.com/").text.strip()
print(my_ip_address)

dns_resolver = dns.resolver.Resolver()
answers = dns_resolver.resolve(MY_DOMAIN, dns.rdatatype.TXT)
for answer in answers:
    answer = str(answer)
    print(answer)
    if not answer.startswith("\"v=spf1"):
        continue
    if my_ip_address in answer:
        print("IP address appears allowed to send email")
        sys.exit(0)
    else:
        print("Wrong IP in SPF")

print("Couldn't find SPF record allowing us to send email")
sys.exit(1)


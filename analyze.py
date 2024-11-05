#!/usr/bin/env python

import click
import django
import dns.flags
import dns.rdatatype
import dns.resolver
import logging
import os
import re
import smtplib
import socket
import ssl
import traceback

from django.conf import settings
from url_normalize import url_normalize
from urllib.parse import urlparse


TIMEOUT_SECONDS = 20

url_re = re.compile("[._a-z0-9]+")


def normalize_domain(domain):
    try:
        if domain:
            return urlparse(url_normalize(domain)).hostname
    except UnicodeError:
        return None


class MxResults:
    def __init__(self, hosts):
        self.hosts = hosts


class Analysis:
    def __init__(self, sender_name):
        self.sender_name = sender_name
        self.dns_resolver = dns.resolver.Resolver()
        # Ask for DNSSEC validation
        self.dns_resolver.edns = 0
        self.dns_resolver.ednsflags |= dns.flags.DO
        # Secure SMTP
        self.ssl_context = ssl.create_default_context()
        # Logging
        self.logger = logging.getLogger(__name__)

    def check_mx_records(self, domain: str):
        mxHosts = None
        try:
            answer = self.dns_resolver.resolve(domain, dns.rdatatype.MX)
            mxHosts = set([])
            for rdata in answer:
                rdata_host = rdata.exchange.to_text()
                if rdata_host == ".":
                    # Special case for disabing MX
                    continue
                host = normalize_domain(rdata_host)
                if host is not None:
                    mxHosts.add(host)
                else:
                    assert False, f"{rdata_host} => {host}"
        except (dns.exception.DNSException):
            pass
        return MxResults(mxHosts)

    def get_domain_by_name(self, name):
        try:
            return Domain.objects.get(pk=name)
        except Domain.DoesNotExist as e:
            return None

    def get_mailhost_by_name(self, name):
        try:
            return MailHost.objects.get(pk=name)
        except MailHost.DoesNotExist as e:
            return None

    def scan(self, domains_list):
        domains = []
        for line in domains_list.readlines():
            normalized = normalize_domain(line.strip())
            if normalized is not None:
                domains.append(normalized)

        self.logger.info("[1/2 - scanning all domains]")
        for domain in domains:
            self.logger.info(f"Checking: {domain}...")
            if self.get_domain_by_name(domain) is not None:
                # Already processed
                continue

            domain_info = Domain(name=domain)
            domain_info.save()
            mxResults = self.check_mx_records(domain)
            if mxResults.hosts:
                for host in mxResults.hosts:
                    o = self.get_mailhost_by_name(host)
                    if o is None:
                        self.logger.info(f"  checking {host}")
                        o = self.lookup_mail_host(host)
                    domain_info.mail_hosts.add(o)

    def lookup_mail_host(self, mailhost):
        reachable = False
        error = None
        starttls = None
        pkix_trusted = None

        # Remove trailing dot
        mailhost = mailhost.rstrip('.')

        try:
            with smtplib.SMTP(mailhost, timeout=TIMEOUT_SECONDS) as server:
                # Log and timestamp connection details
                server.set_debuglevel(2)
                r = server.ehlo(name=self.sender_name)
                reachable = True
                if r[0] == 250:
                    starttls = server.has_extn("STARTTLS")
                    if starttls:
                        pkix_trusted = False
                        r = server.starttls(context=self.ssl_context)
                        if r[0] == 220:
                            # EHLO again to prove we can send commands over TLS
                            r = server.ehlo(name=self.sender_name)
                            pkix_trusted = True
                        elif r[0] >= 400:
                            self.logger.warning(f"ERROR: {r[0]}")
                            error = r[0]
                        else:
                            self.logger.error(f"Unexpected code: STARTTLS => {r[0]}")
                elif r[0] in [550, 551, 554]:
                    self.logger.warning("BLOCKED")
                elif r[0] >= 400:
                    self.logger.error(f"ERROR: {r[0]}")
                    error = r[0]
                else:
                    self.logger.error(f"Unexpected code: EHLO => {r[0]}")

        except socket.gaierror as e:
            self.logger.info(f"Unreachable: {e}")
        except (OSError, TimeoutError, ConnectionRefusedError) as e:
            self.logger.info(f"Unreachable: {e}")
        except smtplib.SMTPConnectError as e:
            self.logger.warning(f"BLOCKED : {e}")
        except ssl.SSLCertVerificationError as e:
            self.logger.info(traceback.format_exc())
            self.logger.warning("Untrusted: ", mailhost, e)
        except Exception as e:
            self.logger.error("Ooops: ", mailhost, e, type(e).__name__)


        h = MailHost(
                name=mailhost,
                reachable=reachable,
                error=error,
                starttls=starttls,
                pkix_trusted=pkix_trusted,
        )
        h.save()
        return h


@click.command()
@click.argument("domains_list", required=False, type=click.File('r'))
@click.argument("sender_name", required=False)
def main(sender_name, domains_list):
    """
    Analyze domains in the provided list
    """
    if domains_list:
        if not sender_name:
            print("Need to set a sender name")
        else:
            a = Analysis(sender_name)
            a.scan(domains_list)
    else:
        print("Domains with mail server")
        for host in MailHost.objects.filter(
                reachable=True,
                error=None,
        ).prefetch_related():
            for domain in host.domain_set.all():
                print(f"DOMAIN_MX {domain.name} ({host.name})")

        print("Errors")
        for host in MailHost.objects.filter(
                error=True,
        ).prefetch_related():
            for domain in host.domain_set.all():
                print(f"{domain.name} ({host.name})")

        print("\n\n\n")
        print("No STARTTLS support")
        for host in MailHost.objects.filter(
                reachable=True,
                error=None,
                starttls=False,
        ).prefetch_related():
            for domain in host.domain_set.all():
                print(f"NOSTARTTLS {domain.name} ({host.name})")

        print("\n\n\n")
        print("Untrusted certificates")
        for host in MailHost.objects.filter(
                reachable=True,
                error=None,
                starttls=True,
                pkix_trusted=False,
        ).prefetch_related():
            for domain in host.domain_set.all():
                print(f"UNTRUSTED {domain.name} ({host.name})")



if __name__ == "__main__":
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
    django.setup()
    from db.models import *
    main()


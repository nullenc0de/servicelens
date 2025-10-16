#!/usr/bin/env python3

import argparse
import dns.resolver
import xml.etree.ElementTree as ET
from urllib.request import urlopen, Request
from collections import defaultdict
import re
import json
import sys
from datetime import datetime

def get_m365_domains(domain):
    body = f"""<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
        xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
        xmlns:a="http://www.w3.org/2005/08/addressing"
        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <soap:Header>
        <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
        <a:MessageID>urn:uuid:6389558d-9e05-465e-ade9-aae14c4bcd10</a:MessageID>
        <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
        <a:To soap:mustUnderstand="1">https://autodiscover.byfcxu-dom.extest.microsoft.com/autodiscover/autodiscover.svc</a:To>
        <a:ReplyTo>
        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
    </soap:Header>
    <soap:Body>
        <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
        <Request>
            <Domain>{domain}</Domain>
        </Request>
        </GetFederationInformationRequestMessage>
    </soap:Body>
    </soap:Envelope>"""

    headers = {
        "Content-type": "text/xml; charset=utf-8",
        "User-agent": "AutodiscoverClient"
    }

    try:
        httprequest = Request(
            "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc", headers=headers, data=body.encode())

        with urlopen(httprequest) as response:
            response = response.read().decode()
    except Exception as e:
        print(f"[-] Unable to execute request: {e}")
        return []

    domains = []
    tree = ET.fromstring(response)
    for elem in tree.iter():
        if elem.tag == "{http://schemas.microsoft.com/exchange/2010/Autodiscover}Domain":
            domains.append(elem.text)

    return domains

def check_txt_records(domain):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        return [str(record) for record in txt_records]
    except Exception as e:
        return []

def check_dmarc(domain):
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        return [str(record) for record in dmarc_records if "v=DMARC1" in str(record)]
    except Exception as e:
        return []

def parse_dmarc_policy(dmarc_records):
    """Parse DMARC records and extract key policy information"""
    dmarc_info = {}
    for record in dmarc_records:
        # Extract policy
        if "p=reject" in record:
            dmarc_info['policy'] = 'reject'
        elif "p=quarantine" in record:
            dmarc_info['policy'] = 'quarantine'
        elif "p=none" in record:
            dmarc_info['policy'] = 'none'

        # Extract percentage
        pct_match = re.search(r'pct=(\d+)', record)
        if pct_match:
            dmarc_info['percentage'] = pct_match.group(1)

        # Extract reporting addresses
        rua_match = re.search(r'rua=mailto:([^;]+)', record)
        if rua_match:
            dmarc_info['aggregate_reports'] = rua_match.group(1).split(',')

    return dmarc_info

def check_mx_records(domain):
    """Check MX records to identify mail servers"""
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [(record.preference, str(record.exchange)) for record in mx_records]
    except Exception as e:
        return []

def check_ns_records(domain):
    """Check nameserver records"""
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        return [str(record) for record in ns_records]
    except Exception as e:
        return []

def check_cname_records(subdomain):
    """Check CNAME records for subdomains"""
    try:
        cname_records = dns.resolver.resolve(subdomain, 'CNAME')
        return [str(record) for record in cname_records]
    except Exception as e:
        return []

def check_dkim_records(domain):
    """Check common DKIM selector records"""
    selectors = ['default', 'google', 'k1', 'k2', 'selector1', 'selector2',
                 'dkim', 's1', 's2', 'mail', 'email', 'mx']
    dkim_records = {}
    for selector in selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            records = dns.resolver.resolve(dkim_domain, 'TXT')
            dkim_records[selector] = [str(record) for record in records]
        except Exception:
            pass
    return dkim_records

def check_bimi_record(domain):
    """Check for BIMI (Brand Indicators for Message Identification) record"""
    try:
        bimi_records = dns.resolver.resolve(f"default._bimi.{domain}", 'TXT')
        return [str(record) for record in bimi_records if "v=BIMI1" in str(record)]
    except Exception as e:
        return []

def check_mta_sts(domain):
    """Check for MTA-STS (Mail Transfer Agent Strict Transport Security) record"""
    try:
        mta_sts_records = dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        return [str(record) for record in mta_sts_records if "v=STSv1" in str(record)]
    except Exception as e:
        return []

def check_smtp_tls_reporting(domain):
    """Check for SMTP TLS Reporting (TLS-RPT) record"""
    try:
        tls_rpt_records = dns.resolver.resolve(f"_smtp._tls.{domain}", 'TXT')
        return [str(record) for record in tls_rpt_records if "v=TLSRPTv1" in str(record)]
    except Exception as e:
        return []

def check_caa_records(domain):
    """Check CAA (Certification Authority Authorization) records"""
    try:
        caa_records = dns.resolver.resolve(domain, 'CAA')
        return [(record.flags, record.tag.decode(), record.value.decode()) for record in caa_records]
    except Exception as e:
        return []

def check_a_records(domain):
    """Check A records (IPv4 addresses)"""
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        return [str(record) for record in a_records]
    except Exception as e:
        return []

def check_aaaa_records(domain):
    """Check AAAA records (IPv6 addresses)"""
    try:
        aaaa_records = dns.resolver.resolve(domain, 'AAAA')
        return [str(record) for record in aaaa_records]
    except Exception as e:
        return []

def check_soa_record(domain):
    """Check SOA (Start of Authority) record"""
    try:
        soa_records = dns.resolver.resolve(domain, 'SOA')
        soa = soa_records[0]
        return {
            'mname': str(soa.mname),
            'rname': str(soa.rname),
            'serial': soa.serial,
            'refresh': soa.refresh,
            'retry': soa.retry,
            'expire': soa.expire,
            'minimum': soa.minimum
        }
    except Exception as e:
        return {}

def check_srv_records(domain):
    """Check common SRV records for various services"""
    srv_services = [
        '_caldav._tcp', '_caldavs._tcp',
        '_carddav._tcp', '_carddavs._tcp',
        '_xmpp-client._tcp', '_xmpp-server._tcp',
        '_jabber._tcp', '_sip._tcp', '_sips._tcp',
        '_ldap._tcp', '_kerberos._tcp',
        '_autodiscover._tcp'
    ]
    srv_records = {}
    for service in srv_services:
        try:
            srv_domain = f"{service}.{domain}"
            records = dns.resolver.resolve(srv_domain, 'SRV')
            srv_records[service] = [(r.priority, r.weight, r.port, str(r.target)) for r in records]
        except Exception:
            pass
    return srv_records

def check_spf(domain):
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        return [str(record) for record in spf_records if "v=spf1" in str(record)]
    except Exception as e:
        return []

def extract_services(records):
    services = set()
    domain_pattern = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}')

    for record in records:
        domains = domain_pattern.findall(record)
        services.update(domains)

        if "include:" in record:
            services.update(domain.strip() for domain in record.split("include:")[1:])

    return services

def validate_subdomain(subdomain, verbose=False):
    if verbose:
        print(f"\nValidating subdomain: {subdomain}")

    # Collect all DNS records
    txt_records = check_txt_records(subdomain)
    dmarc_records = check_dmarc(subdomain)
    spf_records = check_spf(subdomain)
    mx_records = check_mx_records(subdomain)
    ns_records = check_ns_records(subdomain)
    dkim_records = check_dkim_records(subdomain)
    bimi_records = check_bimi_record(subdomain)
    mta_sts_records = check_mta_sts(subdomain)
    tls_rpt_records = check_smtp_tls_reporting(subdomain)
    caa_records = check_caa_records(subdomain)
    a_records = check_a_records(subdomain)
    aaaa_records = check_aaaa_records(subdomain)
    soa_record = check_soa_record(subdomain)
    srv_records = check_srv_records(subdomain)

    if verbose:
        print(f"TXT Records: {txt_records}")
        print(f"DMARC Records: {dmarc_records}")
        print(f"SPF Records: {spf_records}")
        print(f"MX Records: {mx_records}")
        print(f"NS Records: {ns_records}")
        print(f"DKIM Records: {dkim_records}")
        print(f"BIMI Records: {bimi_records}")
        print(f"MTA-STS Records: {mta_sts_records}")
        print(f"TLS-RPT Records: {tls_rpt_records}")
        print(f"CAA Records: {caa_records}")
        print(f"A Records: {a_records}")
        print(f"AAAA Records: {aaaa_records}")
        print(f"SOA Record: {soa_record}")
        print(f"SRV Records: {srv_records}")

    services = extract_services(txt_records + dmarc_records + spf_records)

    # Extract mail servers from MX records
    for _, mx_server in mx_records:
        mx_domain_match = re.search(r'([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})', mx_server)
        if mx_domain_match:
            services.add(mx_domain_match.group(1))

    if verbose:
        print(f"Subdomain appears to be {'valid' if services else 'invalid'}")

    return services, {
        'dmarc': dmarc_records,
        'spf': spf_records,
        'mx': mx_records,
        'ns': ns_records,
        'txt': txt_records,
        'dkim': dkim_records,
        'bimi': bimi_records,
        'mta_sts': mta_sts_records,
        'tls_rpt': tls_rpt_records,
        'caa': caa_records,
        'a': a_records,
        'aaaa': aaaa_records,
        'soa': soa_record,
        'srv': srv_records
    }

def categorize_services(all_services):
    service_categories = {
        'Email Services': defaultdict(set),
        'Cloud Platforms': defaultdict(set),
        'Analytics and Surveys': defaultdict(set),
        'Customer Support': defaultdict(set),
        'Security and Training': defaultdict(set),
        'Marketing and CRM': defaultdict(set),
        'Productivity and Collaboration': defaultdict(set),
        'Development and Version Control': defaultdict(set),
        'Content Delivery and Hosting': defaultdict(set),
        'Payment and Financial Services': defaultdict(set),
        'Uncategorized Services': defaultdict(set)
    }

    known_services = {
        'Email Services': ['outlook', 'gmail', 'yahoo', 'sendgrid', 'mailchimp', 'amazonses', 'zoho', 'postmark', 'mandrill', 'mailgun', 'sparkpost', 'protonmail', 'fastmail', 'sendpulse', 'sendinblue', 'mailjet', 'constantcontact', 'campaignmonitor', 'icontact', 'getresponse', 'aweber', 'activecampaign', 'drip', 'convertkit', 'pphosted'],
        'Cloud Platforms': ['aws', 'azure', 'googlecloud', 'digitalocean', 'heroku', 'linode', 'vultr', 'rackspace', 'ibmcloud', 'oracle', 'onmicrosoft', 'protection.outlook', 'cloudflare', 'fastly', 'akamai', 'cdn77', 'maxcdn', 'stackpath', 'cloudflarenet', 'salesforce', 'force.com', 'mongodb'],
        'Analytics and Surveys': ['google-analytics', 'googletagmanager', 'hotjar', 'mixpanel', 'kissmetrics', 'qualtrics', 'surveymonkey', 'typeform', 'segment', 'amplitude', 'heap', 'pendo', 'fullstory', 'optimizely', 'crazyegg', 'clicktale', 'mouseflow', 'luckyorange'],
        'Customer Support': ['zendesk', 'freshdesk', 'helpscout', 'intercom', 'drift', 'tawk', 'livechat', 'olark', 'uservoice', 'desk.com', 'gorgias', 'kustomer', 'gladly', 'frontapp', 'helpwise', 'kayako', 'zopim', 'snapengage'],
        'Security and Training': ['cloudflare', 'akamai', 'imperva', 'zscaler', 'proofpoint', 'mimecast', 'knowbe4', 'dmarcian', 'barracuda', 'symantec', 'mcafee', 'trend', 'sophos', 'kaspersky', 'bitdefender', 'malwarebytes', 'crowdstrike', 'carbonblack', 'cylance', 'sentinelone', 'fireeye', 'paloaltonetworks', 'fortinet', 'globalsign'],
        'Marketing and CRM': ['hubspot', 'salesforce', 'marketo', 'eloqua', 'pardot', 'mailchimp', 'exacttarget', 'constantcontact', 'campaignmonitor', 'getresponse', 'activecampaign', 'drip', 'pipedrive', 'zoho', 'freshsales', 'insightly', 'nutshell', 'agilecrm', 'sugarcrm'],
        'Productivity and Collaboration': ['office365', 'gsuite', 'google.workspace', 'zoom', 'slack', 'dropbox', 'box', 'atlassian', 'asana', 'trello', 'basecamp', 'monday', 'notion', 'evernote', 'miro', 'airtable', 'clickup', 'wrike', 'teamwork', 'podio', 'docusign'],
        'Development and Version Control': ['github', 'gitlab', 'bitbucket', 'jira', 'confluence', 'circleci', 'travis-ci', 'jenkins', 'teamcity', 'azure.devops', 'dockerhub', 'npmjs', 'rubygems', 'pypi', 'sonarqube', 'sentry'],
        'Content Delivery and Hosting': ['cloudflare', 'akamai', 'fastly', 'cdn77', 'maxcdn', 'stackpath', 'aws.cloudfront', 'azure.cdn', 'google.cloud.cdn', 'netlify', 'vercel', 'heroku', 'wpengine', 'pantheon', 'acquia', 'godaddy', 'bluehost', 'hostgator'],
        'Payment and Financial Services': ['paypal', 'stripe', 'square', 'adyen', 'worldpay', 'cybersource', 'authorize.net', 'braintree', '2checkout', 'wepay', 'quickbooks', 'xero', 'freshbooks', 'wave', 'zuora', 'chargify', 'recurly', 'chargebee']
    }

    for domain, services in all_services.items():
        for service in services:
            categorized = False
            for category, known_list in known_services.items():
                if any(known in service.lower() for known in known_list):
                    service_categories[category][service].add(domain)
                    categorized = True
                    break
            if not categorized:
                service_categories['Uncategorized Services'][service].add(domain)

    return service_categories

def extract_verification_tokens(dns_info):
    """Extract and categorize verification tokens from TXT records"""
    verifications = defaultdict(list)

    for domain, info in dns_info.items():
        txt_records = info.get('txt', [])

        for record in txt_records:
            record_clean = record.strip('"')

            # Microsoft verification
            if record_clean.startswith('MS='):
                verifications['Microsoft 365'].append(domain)
            # Apple domain verification
            elif 'apple-domain-verification' in record_clean:
                verifications['Apple'].append(domain)
            # DocuSign verification
            elif 'docusign' in record_clean.lower():
                verifications['DocuSign'].append(domain)
            # MongoDB verification
            elif 'mongodb-site-verification' in record_clean:
                verifications['MongoDB'].append(domain)
            # GlobalSign verification
            elif 'globalsign-domain-verification' in record_clean:
                verifications['GlobalSign'].append(domain)
            # Google verification
            elif 'google-site-verification' in record_clean:
                verifications['Google'].append(domain)
            # Adobe IDP verification
            elif 'adobe-idp-site-verification' in record_clean:
                verifications['Adobe IDP'].append(domain)
            # Atlassian verification
            elif 'atlassian-domain-verification' in record_clean:
                verifications['Atlassian'].append(domain)
            # Facebook domain verification
            elif 'facebook-domain-verification' in record_clean:
                verifications['Facebook'].append(domain)
            # Zoom verification
            elif 'zoom-domain-verification' in record_clean:
                verifications['Zoom'].append(domain)
            # Stripe verification
            elif 'stripe-verification' in record_clean:
                verifications['Stripe'].append(domain)
            # Webex verification
            elif 'cisco-ci-domain-verification' in record_clean:
                verifications['Webex/Cisco'].append(domain)

    return verifications

def print_categorized_summary(categorized_services):
    print("\nCategorized Summary of Services:")
    print("=" * 80)

    for category, services in categorized_services.items():
        if services:
            print(f"\n{category}")
            print("-" * len(category))
            for service, domains in sorted(services.items()):
                print(f"  • {service}")
                if len(domains) > 1:
                    print("    Seen in:")
                    for domain in sorted(domains):
                        print(f"     - {domain}")
                else:
                    print(f"    Seen in: {next(iter(domains))}")

def print_verification_summary(dns_info):
    """Print a summary of discovered verification tokens and integrations"""
    verifications = extract_verification_tokens(dns_info)

    if not verifications:
        return

    print("\n" + "=" * 80)
    print("Third-Party Integrations & Verifications")
    print("=" * 80)

    print("\nThe following services have domain ownership verification configured:")
    for service, domains in sorted(verifications.items()):
        count = len(domains)
        if count > 1:
            print(f"  • {service} ({count} verification records)")
        else:
            print(f"  • {service}")

def print_comprehensive_summary(domain, all_services, categorized_services, dns_info):
    """Print a comprehensive, human-readable summary of all findings"""
    print("\n" + "=" * 80)
    print(f"COMPREHENSIVE ANALYSIS SUMMARY: {domain}")
    print("=" * 80)

    # Email Security Status
    domain_info = dns_info.get(domain, {})
    print("\n📧 EMAIL SECURITY STATUS")
    print("-" * 40)

    if domain_info.get('dmarc'):
        dmarc_policy = parse_dmarc_policy(domain_info['dmarc'])
        policy = dmarc_policy.get('policy', 'none')
        pct = dmarc_policy.get('percentage', '0')
        print(f"  DMARC: ✓ Configured (Policy: {policy.upper()}, Enforcement: {pct}%)")
    else:
        print(f"  DMARC: ✗ Not configured - VULNERABLE to email spoofing")

    if domain_info.get('spf'):
        include_count = sum(record.count('include:') for record in domain_info['spf'])
        ip4_count = sum(record.count('ip4:') for record in domain_info['spf'])
        print(f"  SPF: ✓ Configured ({include_count} authorized services, {ip4_count} IP ranges)")
    else:
        print(f"  SPF: ✗ Not configured")

    if domain_info.get('dkim'):
        print(f"  DKIM: ✓ Found {len(domain_info['dkim'])} selector(s)")
    else:
        print(f"  DKIM: ~ No common selectors found")

    # Infrastructure Summary
    print("\n🌐 INFRASTRUCTURE")
    print("-" * 40)

    if domain_info.get('a'):
        print(f"  IPv4 Addresses: {len(domain_info['a'])} address(es)")
        for ip in domain_info['a'][:3]:
            print(f"    - {ip}")
        if len(domain_info['a']) > 3:
            print(f"    ... and {len(domain_info['a']) - 3} more")

    if domain_info.get('mx'):
        print(f"  Mail Servers: {len(domain_info['mx'])} server(s)")
        for priority, server in sorted(domain_info['mx'])[:2]:
            print(f"    [{priority}] {server.rstrip('.')}")

    if domain_info.get('ns'):
        print(f"  Name Servers: {len(domain_info['ns'])} server(s)")
        for ns in domain_info['ns'][:2]:
            print(f"    - {ns.rstrip('.')}")

    # Key Services
    print("\n🔑 KEY SERVICES IDENTIFIED")
    print("-" * 40)

    important_categories = ['Email Services', 'Cloud Platforms', 'Security and Training',
                           'Productivity and Collaboration']

    for category in important_categories:
        services = categorized_services.get(category, {})
        if services:
            print(f"\n  {category}:")
            for service in sorted(services.keys())[:5]:
                print(f"    • {service}")
            if len(services) > 5:
                print(f"    ... and {len(services) - 5} more")

    # Verification Tokens
    verifications = extract_verification_tokens(dns_info)
    if verifications:
        print("\n🔐 VERIFIED INTEGRATIONS")
        print("-" * 40)
        for service, _ in sorted(verifications.items()):
            print(f"  ✓ {service}")

    # Security Recommendations
    print("\n💡 SECURITY RECOMMENDATIONS")
    print("-" * 40)

    recommendations = []

    if not domain_info.get('dmarc') or parse_dmarc_policy(domain_info.get('dmarc', [])).get('policy') != 'reject':
        recommendations.append("Implement DMARC with 'reject' policy to prevent email spoofing")

    if not domain_info.get('mta_sts'):
        recommendations.append("Enable MTA-STS to enforce TLS encryption for email delivery")

    if not domain_info.get('caa'):
        recommendations.append("Configure CAA records to restrict certificate issuance")

    if not domain_info.get('dkim'):
        recommendations.append("Verify DKIM configuration (may be using custom selectors)")

    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    else:
        print("  ✓ No critical security issues identified")

def print_security_summary(dns_info):
    """Print a comprehensive security summary including email, TLS, and certificate policies"""
    print("\n" + "=" * 80)
    print("Security Posture Summary")
    print("=" * 80)

    for domain, info in dns_info.items():
        print(f"\n[{domain}]")

        # DMARC Analysis
        if info['dmarc']:
            dmarc_info = parse_dmarc_policy(info['dmarc'])
            print(f"\n  DMARC Configuration:")
            policy = dmarc_info.get('policy', 'not set')
            if policy == 'reject':
                print(f"    ✓ Policy: {policy.upper()} (Strong)")
            elif policy == 'quarantine':
                print(f"    ⚠ Policy: {policy.upper()} (Moderate)")
            elif policy == 'none':
                print(f"    ✗ Policy: {policy.upper()} (Weak - monitoring only)")
            else:
                print(f"    ✗ Policy: {policy}")

            if 'percentage' in dmarc_info:
                pct = int(dmarc_info['percentage'])
                if pct == 100:
                    print(f"    ✓ Enforcement: {pct}% (Full)")
                else:
                    print(f"    ⚠ Enforcement: {pct}% (Partial)")

            if 'aggregate_reports' in dmarc_info:
                print(f"    ℹ Reporting to: {', '.join(dmarc_info['aggregate_reports'][:2])}")
        else:
            print(f"  ✗ DMARC: Not configured (Email spoofing vulnerability)")

        # SPF Analysis
        if info['spf']:
            print(f"\n  SPF Configuration:")
            print(f"    ✓ SPF record present")
            # Count authorized senders
            include_count = sum(record.count('include:') for record in info['spf'])
            ip4_count = sum(record.count('ip4:') for record in info['spf'])
            if include_count > 0:
                print(f"    ℹ Authorized services: {include_count}")
            if ip4_count > 0:
                print(f"    ℹ Authorized IP ranges: {ip4_count}")
        else:
            print(f"  ✗ SPF: Not configured")

        # DKIM Analysis
        if info.get('dkim'):
            print(f"\n  DKIM Configuration:")
            print(f"    ✓ Found {len(info['dkim'])} DKIM selector(s): {', '.join(info['dkim'].keys())}")
        else:
            print(f"\n  ⚠ DKIM: No common selectors found (may be using custom selectors)")

        # MTA-STS Analysis
        if info.get('mta_sts'):
            print(f"\n  MTA-STS (SMTP Security):")
            print(f"    ✓ MTA-STS enabled (Enforces TLS for mail transfer)")
        else:
            print(f"\n  ⚠ MTA-STS: Not configured (SMTP connections may be unencrypted)")

        # TLS-RPT Analysis
        if info.get('tls_rpt'):
            print(f"\n  TLS Reporting:")
            print(f"    ✓ TLS-RPT configured (TLS failure reporting enabled)")

        # BIMI Analysis
        if info.get('bimi'):
            print(f"\n  BIMI (Brand Indicators):")
            print(f"    ✓ BIMI record present (Brand logo authentication)")

        # CAA Analysis
        if info.get('caa'):
            print(f"\n  CAA (Certificate Authority Authorization):")
            print(f"    ✓ CAA records configured")
            for flags, tag, value in info['caa']:
                if tag == 'issue':
                    print(f"    ℹ Authorized CA: {value}")
                elif tag == 'issuewild':
                    print(f"    ℹ Wildcard CA: {value}")
                elif tag == 'iodef':
                    print(f"    ℹ Violation reports: {value}")
        else:
            print(f"\n  ⚠ CAA: Not configured (Any CA can issue certificates)")

        # MX Records
        if info['mx']:
            print(f"\n  Mail Servers (MX):")
            for priority, server in sorted(info['mx']):
                print(f"    [{priority}] {server}")

        # A/AAAA Records (IP addresses)
        if info.get('a'):
            print(f"\n  IPv4 Addresses (A):")
            for ip in info['a']:
                print(f"    {ip}")

        if info.get('aaaa'):
            print(f"  IPv6 Addresses (AAAA):")
            for ip in info['aaaa']:
                print(f"    {ip}")

        # SOA Record
        if info.get('soa'):
            soa = info['soa']
            print(f"\n  DNS Zone Info (SOA):")
            print(f"    Primary NS: {soa.get('mname', 'N/A')}")
            print(f"    Responsible: {soa.get('rname', 'N/A')}")
            print(f"    Serial: {soa.get('serial', 'N/A')}")

        # SRV Records
        if info.get('srv'):
            print(f"\n  Service Records (SRV):")
            for service, records in info['srv'].items():
                print(f"    {service}:")
                for priority, weight, port, target in records:
                    print(f"      [{priority}:{weight}] {target}:{port}")

def export_json(all_services, dns_info, output_file):
    """Export comprehensive results to JSON format"""
    export_data = {
        'timestamp': datetime.now().isoformat(),
        'domains': {}
    }

    for domain in all_services.keys():
        domain_info = dns_info.get(domain, {})

        export_data['domains'][domain] = {
            'services': list(all_services[domain]),
            'dns_records': {
                'dmarc': domain_info.get('dmarc', []),
                'spf': domain_info.get('spf', []),
                'mx': [{'priority': p, 'server': s} for p, s in domain_info.get('mx', [])],
                'ns': domain_info.get('ns', []),
                'txt': domain_info.get('txt', []),
                'dkim': domain_info.get('dkim', {}),
                'bimi': domain_info.get('bimi', []),
                'mta_sts': domain_info.get('mta_sts', []),
                'tls_rpt': domain_info.get('tls_rpt', []),
                'caa': [{'flags': f, 'tag': t, 'value': v} for f, t, v in domain_info.get('caa', [])],
                'a': domain_info.get('a', []),
                'aaaa': domain_info.get('aaaa', []),
                'soa': domain_info.get('soa', {}),
                'srv': domain_info.get('srv', {})
            }
        }

        # Add parsed DMARC policy
        if domain_info.get('dmarc'):
            export_data['domains'][domain]['dmarc_policy'] = parse_dmarc_policy(
                domain_info['dmarc']
            )

        # Add security score
        security_score = 0
        max_score = 6

        if domain_info.get('dmarc'):
            dmarc_policy = parse_dmarc_policy(domain_info['dmarc'])
            if dmarc_policy.get('policy') == 'reject':
                security_score += 2
            elif dmarc_policy.get('policy') == 'quarantine':
                security_score += 1

        if domain_info.get('spf'):
            security_score += 1
        if domain_info.get('dkim'):
            security_score += 1
        if domain_info.get('mta_sts'):
            security_score += 1
        if domain_info.get('caa'):
            security_score += 1

        export_data['domains'][domain]['security_score'] = {
            'score': security_score,
            'max_score': max_score,
            'percentage': round((security_score / max_score) * 100, 1),
            'rating': 'Excellent' if security_score >= 5 else 'Good' if security_score >= 4 else 'Fair' if security_score >= 2 else 'Poor'
        }

    with open(output_file, 'w') as f:
        json.dump(export_data, f, indent=2)

    print(f"\n[+] Results exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="ServiceLens: Enumerate services and analyze DNS security for Microsoft 365 domains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python servicelens.py -d example.com
  python servicelens.py -d example.com -v
  python servicelens.py -d example.com --security-report
  python servicelens.py -d example.com -o results.json
        """
    )
    parser.add_argument("-d", "--domain", help="Input domain name (e.g., example.com)", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", help="Export results to JSON file", metavar="FILE")
    parser.add_argument("--security-report", action="store_true", help="Display email security posture summary")
    parser.add_argument("--no-m365", action="store_true", help="Skip Microsoft 365 domain enumeration")
    args = parser.parse_args()

    print(f"[*] ServiceLens - Domain Analysis Tool")
    print(f"[*] Target: {args.domain}\n")

    all_services = defaultdict(set)
    dns_info = {}

    # M365 domain enumeration
    if not args.no_m365:
        print(f"[*] Enumerating Microsoft 365 domains for {args.domain}...")
        m365_domains = get_m365_domains(args.domain)

        if m365_domains:
            print(f"[+] Found {len(m365_domains)} Microsoft 365 domain(s):")
            for domain in m365_domains:
                print(f"    - {domain}")
                services, info = validate_subdomain(domain, args.verbose)
                all_services[domain].update(services)
                dns_info[domain] = info
        else:
            print("[-] No Microsoft 365 domains found.")

    # Validate the original domain
    print(f"\n[*] Analyzing primary domain: {args.domain}")
    services, info = validate_subdomain(args.domain, args.verbose)
    all_services[args.domain].update(services)
    dns_info[args.domain] = info

    if args.verbose:
        print("\n" + "=" * 80)
        print("Detailed Summary of Services")
        print("=" * 80)
        for domain, services in all_services.items():
            print(f"\n{domain}:")
            for service in sorted(services):
                print(f"  - {service}")

    # Print categorized services
    categorized_services = categorize_services(all_services)
    print_categorized_summary(categorized_services)

    # Print verification tokens summary
    print_verification_summary(dns_info)

    # Print comprehensive summary
    print_comprehensive_summary(args.domain, all_services, categorized_services, dns_info)

    # Security report
    if args.security_report:
        print_security_summary(dns_info)

    # Export to JSON
    if args.output:
        export_json(all_services, dns_info, args.output)

    print(f"\n[*] Analysis complete!")

if __name__ == "__main__":
    main()

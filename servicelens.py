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

def check_subdomain_takeover(domain):
    """
    Check for potential subdomain takeover vulnerabilities
    Looks for dangling CNAMEs pointing to cloud services
    """
    vulnerable_patterns = {
        'amazonaws.com': 'AWS/S3',
        'azurewebsites.net': 'Azure',
        'cloudapp.net': 'Azure',
        'herokuapp.com': 'Heroku',
        'netlify.app': 'Netlify',
        'github.io': 'GitHub Pages',
        'vercel.app': 'Vercel',
        'gitlab.io': 'GitLab Pages',
        'bitbucket.io': 'Bitbucket',
        'surge.sh': 'Surge',
        'ghost.io': 'Ghost',
        'pantheonsite.io': 'Pantheon',
        'fastly.net': 'Fastly',
        'zendesk.com': 'Zendesk',
        'desk.com': 'Desk.com',
        'helpscoutdocs.com': 'Help Scout',
        'teamwork.com': 'Teamwork',
        'helpjuice.com': 'Helpjuice'
    }

    # Common subdomains to check
    common_subdomains = ['www', 'blog', 'dev', 'staging', 'test', 'api', 'app', 'portal', 'docs', 'help', 'support']

    findings = []

    for subdomain_prefix in common_subdomains:
        subdomain = f"{subdomain_prefix}.{domain}"
        try:
            # Try to resolve CNAME
            cname_records = dns.resolver.resolve(subdomain, 'CNAME')
            for cname in cname_records:
                cname_target = str(cname.target)

                # Check if it points to a cloud service
                for pattern, service in vulnerable_patterns.items():
                    if pattern in cname_target:
                        # Try to resolve the target to see if it's dangling
                        try:
                            dns.resolver.resolve(cname_target, 'A')
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            findings.append({
                                'subdomain': subdomain,
                                'cname_target': cname_target,
                                'service': service,
                                'risk': 'HIGH'
                            })
                        break
        except:
            pass  # Subdomain doesn't exist or has no CNAME

    return findings

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

def analyze_spf_record(spf_records, domain, visited=None):
    """
    Analyze SPF record for DNS lookup count and dangerous qualifiers
    Returns: {
        'lookup_count': int,
        'includes': list,
        'dangerous_qualifiers': list,
        'warnings': list
    }
    """
    if visited is None:
        visited = set()

    if domain in visited:
        return {'lookup_count': 0, 'includes': [], 'dangerous_qualifiers': [], 'warnings': ['Circular SPF reference detected']}

    visited.add(domain)

    analysis = {
        'lookup_count': 0,
        'includes': [],
        'dangerous_qualifiers': [],
        'warnings': []
    }

    for record in spf_records:
        record_clean = record.strip('"')

        # Check for dangerous qualifiers
        if ' +all' in record_clean or record_clean.endswith('+all'):
            analysis['dangerous_qualifiers'].append('+all (CRITICAL: Allows any server to send)')
        elif ' ?all' in record_clean or record_clean.endswith('?all'):
            analysis['dangerous_qualifiers'].append('?all (Neutral: No protection)')

        # Count mechanisms that cause DNS lookups
        # include, a, mx, ptr, exists count as lookups
        lookups = (
            record_clean.count('include:') +
            record_clean.count(' a') + record_clean.count(' a:') +
            record_clean.count(' mx') + record_clean.count(' mx:') +
            record_clean.count('ptr') + record_clean.count('ptr:') +
            record_clean.count('exists:')
        )

        analysis['lookup_count'] += lookups

        # Extract includes for reference
        import re
        includes = re.findall(r'include:([^\s]+)', record_clean)
        analysis['includes'].extend(includes)

    # Add warnings
    if analysis['lookup_count'] > 10:
        analysis['warnings'].append(f"SPF lookup limit EXCEEDED: {analysis['lookup_count']}/10 (RFC 7208)")
    elif analysis['lookup_count'] >= 8:
        analysis['warnings'].append(f"SPF lookups approaching limit: {analysis['lookup_count']}/10")

    return analysis

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
            # Slack verification
            elif 'slack-site-verification' in record_clean:
                verifications['Slack'].append(domain)
            # GitHub verification
            elif 'github-domain-verification' in record_clean or 'github-challenge' in record_clean:
                verifications['GitHub'].append(domain)
            # Okta verification
            elif 'okta-domain-verification' in record_clean:
                verifications['Okta'].append(domain)

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

def analyze_phishing_risks(categorized_services, dns_info):
    """Analyze potential phishing and impersonation risks based on verified services"""
    high_risk_services = []

    # Extract all verified integrations
    verifications = extract_verification_tokens(dns_info)

    # High-value phishing targets with typical attack patterns
    phishing_profiles = {
        'Microsoft 365': {
            'risk': 'HIGH',
            'vectors': ['Password reset emails', 'OneDrive sharing notifications', 'Teams meeting invites', 'Account security alerts'],
            'common_spoofs': ['noreply@microsoft.com', 'account-security@microsoft.com']
        },
        'Google': {
            'risk': 'HIGH',
            'vectors': ['Gmail security alerts', 'Google Drive sharing', 'Calendar invites', '2FA notifications'],
            'common_spoofs': ['no-reply@google.com', 'accounts-noreply@google.com']
        },
        'DocuSign': {
            'risk': 'HIGH',
            'vectors': ['Document signing requests', 'Urgent signature needed', 'Contract expiration notices'],
            'common_spoofs': ['dse@docusign.net', 'no-reply@docusign.com']
        },
        'Salesforce': {
            'risk': 'HIGH',
            'vectors': ['Lead notifications', 'Opportunity updates', 'Password reset requests'],
            'common_spoofs': ['noreply@salesforce.com', 'security@salesforce.com']
        },
        'Adobe IDP': {
            'risk': 'MEDIUM',
            'vectors': ['Adobe account security', 'Creative Cloud sharing', 'License expiration'],
            'common_spoofs': ['noreply@adobe.com', 'account@adobe.com']
        },
        'Atlassian': {
            'risk': 'MEDIUM',
            'vectors': ['Jira ticket notifications', 'Confluence page shares', 'Account access requests'],
            'common_spoofs': ['noreply@atlassian.com', 'notifications@atlassian.net']
        },
        'Zoom': {
            'risk': 'MEDIUM',
            'vectors': ['Meeting invitations', 'Recording ready notifications', 'Account security alerts'],
            'common_spoofs': ['no-reply@zoom.us', 'notifications@zoom.us']
        },
        'Apple': {
            'risk': 'MEDIUM',
            'vectors': ['iCloud storage alerts', 'Apple ID security', 'App Store receipts'],
            'common_spoofs': ['no_reply@email.apple.com', 'appleid@id.apple.com']
        },
        'MongoDB': {
            'risk': 'LOW',
            'vectors': ['Database alerts', 'Backup notifications', 'Billing updates'],
            'common_spoofs': ['noreply@mongodb.com']
        },
        'GlobalSign': {
            'risk': 'MEDIUM',
            'vectors': ['Certificate expiration notices', 'Renewal reminders', 'Security alerts'],
            'common_spoofs': ['noreply@globalsign.com']
        },
        'Stripe': {
            'risk': 'HIGH',
            'vectors': ['Payment failed alerts', 'Invoice notifications', 'Account verification required', 'Fraudulent charge alerts'],
            'common_spoofs': ['no-reply@stripe.com', 'support@stripe.com', 'notifications@stripe.com']
        },
        'Facebook': {
            'risk': 'HIGH',
            'vectors': ['Security alert: unusual login', 'Business page access requests', 'Ad account suspension', 'Password reset requests'],
            'common_spoofs': ['security@facebookmail.com', 'notification@facebookmail.com']
        },
        'Slack': {
            'risk': 'HIGH',
            'vectors': ['Workspace invitation', 'Urgent message from admin', 'File sharing notifications', 'App authorization requests'],
            'common_spoofs': ['feedback@slack.com', 'team@slack.com']
        },
        'GitHub': {
            'risk': 'HIGH',
            'vectors': ['Repository access requests', 'OAuth app authorization', 'Security vulnerability alerts', 'Suspicious login attempts'],
            'common_spoofs': ['noreply@github.com', 'support@github.com']
        },
        'Okta': {
            'risk': 'HIGH',
            'vectors': ['Password reset required', 'MFA enrollment', 'Session expired notices', 'Admin role change notifications'],
            'common_spoofs': ['noreply@okta.com', 'do-not-reply@okta.com']
        },
        'Zendesk': {
            'risk': 'MEDIUM',
            'vectors': ['Fake support tickets', 'Account verification emails', 'Password reset requests', 'New ticket created'],
            'common_spoofs': ['support@zendesk.com', 'noreply@zendesk.com']
        },
        'Intercom': {
            'risk': 'MEDIUM',
            'vectors': ['Admin message impersonation', 'Chat transcript phishing', 'Feature update notifications', 'Survey requests'],
            'common_spoofs': ['team@intercom.io', 'via@intercom.io']
        },
        'NetSuite': {
            'risk': 'HIGH',
            'vectors': ['Invoice approval requests', 'Financial report access', 'ERP login alerts', 'Vendor payment notifications'],
            'common_spoofs': ['noreply@netsuite.com', 'notifications@netsuite.com']
        },
        'Duo': {
            'risk': 'MEDIUM',
            'vectors': ['2FA bypass attempts', 'New device enrollment', 'Authentication alerts', 'Admin access requests'],
            'common_spoofs': ['no-reply@duosecurity.com']
        },
        'Marketo': {
            'risk': 'MEDIUM',
            'vectors': ['Marketing email spoofing', 'Campaign impersonation', 'Lead scoring alerts', 'Unsubscribe link phishing'],
            'common_spoofs': ['noreply@marketo.com', 'via@marketo.com']
        }
    }

    # Check email services and other categories for additional risks
    email_services = categorized_services.get('Email Services', {})
    customer_support = categorized_services.get('Customer Support', {})
    uncategorized = categorized_services.get('Uncategorized Services', {})

    # Email services
    if email_services:
        for service in email_services.keys():
            if 'amazonses' in service.lower():
                phishing_profiles['Amazon SES'] = {
                    'risk': 'HIGH',
                    'vectors': ['Transactional emails could be spoofed', 'Order confirmations', 'Account notifications'],
                    'common_spoofs': ['Various - depends on SES sender']
                }
            elif 'proofpoint' in service.lower():
                phishing_profiles['Proofpoint'] = {
                    'risk': 'MEDIUM',
                    'vectors': ['Quarantine notifications', 'Security reports', 'Safe sender requests'],
                    'common_spoofs': ['quarantine@proofpoint.com']
                }

    # Customer support services
    if customer_support:
        for service in customer_support.keys():
            if 'zendesk' in service.lower() and 'Zendesk' not in phishing_profiles:
                pass  # Already in main profiles
            if 'intercom' in service.lower() and 'Intercom' not in phishing_profiles:
                pass  # Already in main profiles

    # Check uncategorized for NetSuite, Marketo, etc.
    if uncategorized:
        for service in uncategorized.keys():
            if 'netsuite' in service.lower() and 'NetSuite' not in phishing_profiles:
                pass  # Already in main profiles
            if 'marketo' in service.lower() and 'Marketo' not in phishing_profiles:
                pass  # Already in main profiles

    # Build risk list based on verified services
    for service_name, profile in phishing_profiles.items():
        # Check if service is verified or in use
        is_verified = service_name in verifications
        is_in_use = False

        # Check if service appears in categorized services
        for category_services in categorized_services.values():
            if any(service_name.lower() in service.lower() for service in category_services.keys()):
                is_in_use = True
                break

        if is_verified or is_in_use:
            high_risk_services.append({
                'name': service_name,
                'risk_level': profile['risk'],
                'attack_vectors': profile['vectors'],
                'spoofed_addresses': profile['common_spoofs'],
                'verified': is_verified
            })

    return sorted(high_risk_services, key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}[x['risk_level']])

def calculate_security_grade(domain_info, phishing_risk_count, subdomain_takeover_count):
    """Calculate overall security grade A-F"""
    score = 100

    # DMARC (30 points)
    if domain_info.get('dmarc'):
        dmarc_policy = parse_dmarc_policy(domain_info['dmarc'])
        policy = dmarc_policy.get('policy', 'none')
        pct = int(dmarc_policy.get('percentage', '100'))

        if pct == 0:
            score -= 30  # Monitoring only = no protection
        elif policy == 'reject' and pct == 100:
            score -= 0  # Perfect
        elif policy == 'reject':
            score -= 10  # Partial enforcement
        elif policy == 'quarantine':
            score -= 15
        else:
            score -= 25
    else:
        score -= 30

    # SPF (20 points)
    if domain_info.get('spf'):
        spf_analysis = analyze_spf_record(domain_info['spf'], domain_info.get('domain', ''))
        if spf_analysis['dangerous_qualifiers']:
            score -= 20  # Critical issue
        elif spf_analysis['lookup_count'] > 10:
            score -= 15
        elif spf_analysis['warnings']:
            score -= 5
    else:
        score -= 20

    # DKIM (15 points)
    if not domain_info.get('dkim'):
        score -= 15

    # MTA-STS (10 points)
    if not domain_info.get('mta_sts'):
        score -= 10

    # CAA (10 points)
    if not domain_info.get('caa'):
        score -= 10

    # Subdomain takeover risks (10 points)
    score -= min(subdomain_takeover_count * 5, 10)

    # High phishing risk services without proper controls (5 points)
    if phishing_risk_count > 5:
        score -= 5

    # Convert to grade
    if score >= 95:
        grade = 'A+'
    elif score >= 90:
        grade = 'A'
    elif score >= 85:
        grade = 'A-'
    elif score >= 80:
        grade = 'B+'
    elif score >= 75:
        grade = 'B'
    elif score >= 70:
        grade = 'B-'
    elif score >= 65:
        grade = 'C+'
    elif score >= 60:
        grade = 'C'
    elif score >= 55:
        grade = 'C-'
    elif score >= 50:
        grade = 'D'
    else:
        grade = 'F'

    return grade, score

def print_comprehensive_summary(domain, all_services, categorized_services, dns_info):
    """Print a comprehensive, human-readable summary of all findings"""
    print("\n" + "=" * 80)
    print("🔒 SECURITY CONFIGURATION & ATTACK SURFACE")
    print("=" * 80)

    # Email Security Status
    domain_info = dns_info.get(domain, {})
    print("\n📧 EMAIL SECURITY STATUS")
    print("-" * 40)

    if domain_info.get('dmarc'):
        dmarc_policy = parse_dmarc_policy(domain_info['dmarc'])
        policy = dmarc_policy.get('policy', 'none')
        pct = int(dmarc_policy.get('percentage', '100'))

        # Check for monitoring mode (pct=0 or missing)
        if pct == 0:
            print(f"  DMARC: ⚠️ MONITORING MODE ONLY (Policy: {policy.upper()}, Enforcement: {pct}%)")
            print(f"         Policy is NOT being enforced! This provides NO protection.")
        elif policy == 'reject' and pct == 100:
            print(f"  DMARC: ✓ Configured (Policy: {policy.upper()}, Enforcement: {pct}%)")
        elif policy == 'reject' or policy == 'quarantine':
            print(f"  DMARC: ⚠️ Partial Enforcement (Policy: {policy.upper()}, Enforcement: {pct}%)")
        else:
            print(f"  DMARC: ✗ Weak Configuration (Policy: {policy.upper()}, Enforcement: {pct}%)")
    else:
        print(f"  DMARC: ✗ Not configured - VULNERABLE to email spoofing")

    if domain_info.get('spf'):
        spf_analysis = analyze_spf_record(domain_info['spf'], domain)
        include_count = len(spf_analysis['includes'])
        ip4_count = sum(record.count('ip4:') for record in domain_info['spf'])

        if spf_analysis['dangerous_qualifiers']:
            print(f"  SPF: ✗ DANGEROUS Configuration - {spf_analysis['dangerous_qualifiers'][0]}")
        elif spf_analysis['warnings']:
            print(f"  SPF: ⚠️ {spf_analysis['warnings'][0]}")
            print(f"       ({include_count} includes, {ip4_count} IP ranges)")
        else:
            print(f"  SPF: ✓ Configured ({include_count} includes, {ip4_count} IP ranges, {spf_analysis['lookup_count']}/10 lookups)")
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

    # Subdomain Takeover Check
    print("\n🔍 SUBDOMAIN TAKEOVER CHECK")
    print("-" * 40)
    subdomain_takeovers = check_subdomain_takeover(domain)
    if subdomain_takeovers:
        print(f"  ⚠️ Found {len(subdomain_takeovers)} potential subdomain takeover vulnerabilities:")
        for finding in subdomain_takeovers:
            print(f"\n  🔴 {finding['subdomain']}")
            print(f"     Points to: {finding['cname_target']}")
            print(f"     Service: {finding['service']}")
            print(f"     Risk: Target appears to be unclaimed!")
    else:
        print(f"  ✓ No obvious subdomain takeover risks detected")

    # Phishing Risk Analysis
    phishing_risks = analyze_phishing_risks(categorized_services, dns_info)
    if phishing_risks:
        print("\n⚠️  PHISHING & IMPERSONATION RISKS")
        print("-" * 40)
        print("\nEmployees may receive phishing emails impersonating these trusted services:")

        for risk in phishing_risks:
            risk_indicator = "🔴" if risk['risk_level'] == 'HIGH' else "🟡" if risk['risk_level'] == 'MEDIUM' else "🟢"
            verified_indicator = " [VERIFIED]" if risk['verified'] else ""
            print(f"\n  {risk_indicator} {risk['name']}{verified_indicator} - {risk['risk_level']} RISK")
            print(f"     Common attack vectors:")
            for vector in risk['attack_vectors'][:3]:
                print(f"       • {vector}")
            if len(risk['spoofed_addresses']) > 0:
                print(f"     Watch for emails from: {', '.join(risk['spoofed_addresses'][:2])}")

    # Overall Security Grade
    grade, score = calculate_security_grade(domain_info, len(phishing_risks), len(subdomain_takeovers))
    print("\n🎯 OVERALL SECURITY GRADE")
    print("-" * 40)

    grade_color = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
    print(f"  {grade_color} Grade: {grade} ({score}/100)")

    if score >= 90:
        print(f"  Excellent security posture!")
    elif score >= 80:
        print(f"  Good security with minor improvements needed")
    elif score >= 70:
        print(f"  Adequate security but has notable gaps")
    elif score >= 60:
        print(f"  Weak security - immediate attention required")
    else:
        print(f"  Poor security - CRITICAL issues need resolution")

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

    if phishing_risks:
        recommendations.append(f"Train employees to recognize phishing attempts from the {len(phishing_risks)} trusted services identified above")
        recommendations.append("Implement email authentication verification (check SPF/DKIM/DMARC alignment)")

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

def get_m365_tenant_info(domain):
    """Get Microsoft 365 tenant information including tenant ID and name"""
    tenant_info = {
        'tenant_id': None,
        'tenant_name': None,
        'cloud_instance': None,
        'tenant_region': None
    }

    try:
        # Get OpenID configuration
        url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
        request = Request(url, headers={"User-agent": "Mozilla/5.0"})
        with urlopen(request) as response:
            data = json.loads(response.read().decode())

            # Extract tenant ID from token endpoint
            token_endpoint = data.get("token_endpoint", "")
            if token_endpoint:
                parts = token_endpoint.split("/")
                if len(parts) > 3:
                    tenant_info['tenant_id'] = parts[3]

            # Extract tenant region
            tenant_info['tenant_region'] = data.get("tenant_region_scope", "Unknown")

            # Extract cloud instance
            issuer = data.get("issuer", "")
            if "microsoftonline.com" in issuer:
                tenant_info['cloud_instance'] = "Commercial"
            elif "microsoftonline.us" in issuer:
                tenant_info['cloud_instance'] = "GCC/GCC-High"
            elif "partner.microsoftonline.cn" in issuer:
                tenant_info['cloud_instance'] = "China"
            else:
                tenant_info['cloud_instance'] = "Unknown"
    except Exception:
        pass

    # Try to get tenant name from M365 domains
    try:
        m365_domains = get_m365_domains(domain)
        for m365_domain in m365_domains:
            if "onmicrosoft.com" in m365_domain:
                tenant_info['tenant_name'] = m365_domain.split(".")[0]
                break
            elif "partner.onmschina.cn" in m365_domain:
                tenant_info['tenant_name'] = m365_domain.split(".")[0]
                tenant_info['cloud_instance'] = "China"
                break
            elif "onmicrosoft.us" in m365_domain:
                tenant_info['tenant_name'] = m365_domain.split(".")[0]
                tenant_info['cloud_instance'] = "GCC/GCC-High"
                break
    except Exception:
        pass

    return tenant_info

def check_azure_ad_federation(domain):
    """Check Azure AD federation status (Managed vs Federated authentication)"""
    federation_info = {
        'auth_type': None,
        'is_federated': False,
        'federation_brand': None,
        'auth_url': None,
        'cloud_instance': None
    }

    try:
        # Use getuserrealm endpoint to check federation
        url = f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&json=1"
        request = Request(url, headers={"User-agent": "Mozilla/5.0"})
        with urlopen(request) as response:
            data = json.loads(response.read().decode())

            # Check namespace type
            namespace_type = data.get("NameSpaceType", "Unknown")
            federation_info['auth_type'] = namespace_type

            # Check if federated
            if data.get("FederationProtocol") or data.get("AuthURL"):
                federation_info['is_federated'] = True
                federation_info['federation_brand'] = data.get("FederationBrandName", "Unknown")
                federation_info['auth_url'] = data.get("AuthURL")

            # Cloud instance
            federation_info['cloud_instance'] = data.get("CloudInstanceName", "Unknown")
    except Exception:
        pass

    return federation_info

def check_mdi_instance(tenant_name):
    """Check for Microsoft Defender for Identity (MDI) deployment"""
    mdi_info = {
        'detected': False,
        'endpoint': None,
        'redteam_implications': []
    }

    if not tenant_name:
        return mdi_info

    try:
        # Check for MDI sensor endpoint
        mdi_endpoint = f"{tenant_name}.atp.azure.com"
        dns.resolver.resolve(mdi_endpoint, 'A')

        mdi_info['detected'] = True
        mdi_info['endpoint'] = mdi_endpoint
        mdi_info['redteam_implications'] = [
            "MDI monitors AD authentication patterns - Kerberos attacks (Golden/Silver tickets, overpass-the-hash) will be detected",
            "Lateral movement techniques (remote execution, NTLM relay) are actively monitored and alerted",
            "Suspicious account enumeration and reconnaissance activities are logged",
            "Consider AMSI bypass for post-exploitation and use of legitimate admin tools to blend in"
        ]
    except Exception:
        pass

    return mdi_info

def check_oauth_applications(tenant_id, domain):
    """Check for exposed Azure AD applications and OAuth attack surfaces"""
    oauth_info = {
        'enterprise_apps_accessible': False,
        'admin_consent_endpoint': None,
        'exposed_app_ids': [],
        'multi_tenant_apps': [],
        'oauth_risks': [],
        'endpoints_accessible': []
    }

    if not tenant_id:
        return oauth_info

    # Check enterprise applications endpoint
    try:
        enterprise_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        request = Request(enterprise_url, headers={"User-agent": "Mozilla/5.0"})
        response = urlopen(request)
        if response.status == 200:
            oauth_info['enterprise_apps_accessible'] = True
            oauth_info['endpoints_accessible'].append(enterprise_url)

            # Look for exposed application IDs
            content = response.read().decode()
            app_ids = re.findall(r'client_id=([0-9a-f-]{36})', content)
            if app_ids:
                oauth_info['exposed_app_ids'] = list(set(app_ids))
                oauth_info['oauth_risks'].append(f"Found {len(oauth_info['exposed_app_ids'])} exposed enterprise application IDs - Potential OAuth abuse targets")
    except Exception:
        pass

    # Check admin consent endpoint
    try:
        admin_consent_url = f"https://login.microsoftonline.com/{tenant_id}/adminconsent"
        request = Request(admin_consent_url, headers={"User-agent": "Mozilla/5.0"})
        response = urlopen(request)
        if response.status in [200, 401, 403]:
            oauth_info['admin_consent_endpoint'] = admin_consent_url
            oauth_info['oauth_risks'].append("Admin consent endpoint is accessible - Check for consent phishing opportunities")
    except Exception:
        pass

    # Check device code flow endpoint (often used in phishing)
    try:
        devicecode_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
        request = Request(devicecode_url, headers={"User-agent": "Mozilla/5.0"})
        response = urlopen(request)
        if response.status in [200, 401, 403]:
            oauth_info['endpoints_accessible'].append(devicecode_url)
            oauth_info['oauth_risks'].append("Device code flow endpoint accessible - Can be used for device code phishing attacks")
    except Exception:
        pass

    return oauth_info

def check_legacy_auth(tenant_id, domain):
    """Check if legacy authentication protocols are enabled"""
    legacy_auth_info = {
        'exchange_legacy_enabled': False,
        'activesync_enabled': False,
        'risks': []
    }

    if not tenant_id:
        return legacy_auth_info

    # Check Exchange Web Services (EWS) legacy auth
    try:
        ews_url = f"https://outlook.office365.com/EWS/Exchange.asmx"
        request = Request(ews_url, headers={"User-agent": "Mozilla/5.0"})
        response = urlopen(request)
        if response.status in [401, 403]:  # Requires auth = endpoint exists
            legacy_auth_info['exchange_legacy_enabled'] = True
            legacy_auth_info['risks'].append("Exchange Web Services (EWS) legacy auth may be enabled - Bypasses MFA")
    except Exception:
        pass

    # Check ActiveSync
    try:
        activesync_url = f"https://outlook.office365.com/Microsoft-Server-ActiveSync"
        request = Request(activesync_url, headers={"User-agent": "Mozilla/5.0"})
        response = urlopen(request)
        if response.status in [401, 403]:  # Requires auth = endpoint exists
            legacy_auth_info['activesync_enabled'] = True
            legacy_auth_info['risks'].append("ActiveSync endpoint accessible - Legacy auth vector that may bypass MFA")
    except Exception:
        pass

    return legacy_auth_info

def check_azure_services(domain):
    """Check for publicly accessible Azure services"""
    azure_services = {
        'app_services': [],
        'storage_accounts': [],
        'cdn_endpoints': [],
        'key_vaults': []
    }

    domain_prefix = domain.split('.')[0]

    # Check Azure App Services
    try:
        app_service_url = f"{domain_prefix}.azurewebsites.net"
        dns.resolver.resolve(app_service_url, 'A')
        azure_services['app_services'].append(app_service_url)
    except Exception:
        pass

    # Check Azure Storage Accounts (common patterns)
    storage_patterns = [
        f"{domain_prefix}.blob.core.windows.net",
        f"{domain_prefix}storage.blob.core.windows.net",
        f"storage{domain_prefix}.blob.core.windows.net"
    ]

    for storage_url in storage_patterns:
        try:
            dns.resolver.resolve(storage_url, 'A')
            azure_services['storage_accounts'].append(storage_url)
        except Exception:
            pass

    # Check Azure CDN
    cdn_patterns = [
        f"{domain_prefix}.azureedge.net",
        f"{domain_prefix}-cdn.azureedge.net",
        f"cdn-{domain_prefix}.azureedge.net"
    ]

    for cdn_url in cdn_patterns:
        try:
            dns.resolver.resolve(cdn_url, 'A')
            azure_services['cdn_endpoints'].append(cdn_url)
        except Exception:
            pass

    # Check Key Vault
    try:
        keyvault_url = f"{domain_prefix}.vault.azure.net"
        dns.resolver.resolve(keyvault_url, 'A')
        azure_services['key_vaults'].append(keyvault_url)
    except Exception:
        pass

    return azure_services

def print_m365_azure_summary(domain, m365_info, federation_info, mdi_info, oauth_info, legacy_auth_info, azure_services):
    """Print comprehensive Microsoft 365 and Azure AD reconnaissance summary"""

    # Only print if we have M365/Azure information
    if not any([m365_info['tenant_id'], federation_info['auth_type'],
                mdi_info['detected'], oauth_info['oauth_risks'],
                legacy_auth_info['risks'], any(azure_services.values())]):
        return

    print("\n" + "=" * 80)
    print("☁️  MICROSOFT 365 & AZURE AD SECURITY POSTURE")
    print("=" * 80)

    # Tenant Information
    if m365_info['tenant_id'] or m365_info['tenant_name']:
        print("\n📋 TENANT INFORMATION")
        print("-" * 40)
        if m365_info['tenant_name']:
            print(f"  Tenant Name: {m365_info['tenant_name']}.onmicrosoft.com")
        if m365_info['tenant_id']:
            print(f"  Tenant ID: {m365_info['tenant_id']}")
        if m365_info['cloud_instance']:
            print(f"  Cloud Instance: {m365_info['cloud_instance']}")
        if m365_info['tenant_region']:
            print(f"  Tenant Region: {m365_info['tenant_region']}")

    # Federation Status
    if federation_info['auth_type']:
        print("\n🔐 IDENTITY CONFIGURATION")
        print("-" * 40)

        auth_type = federation_info['auth_type']
        if auth_type == "Managed":
            print("  Authentication: ✓ Cloud-Only (Managed)")
            print("  └─ All authentication handled in Azure AD")
            print("  └─ No on-premises Active Directory integration")
            print("  └─ Attack Focus: OAuth phishing, device code flow, password spray")
        elif auth_type == "Federated":
            print("  Authentication: ⚠️ Hybrid/Federated")
            print("  └─ On-premises Active Directory integration detected")
            if federation_info['federation_brand']:
                print(f"  └─ Federation Provider: {federation_info['federation_brand']}")
            if federation_info['auth_url']:
                print(f"  └─ Auth URL: {federation_info['auth_url']}")
            print("  └─ Attack Focus: Both cloud AND on-premises vectors")
        else:
            print(f"  Authentication: {auth_type}")

    # Microsoft Defender for Identity
    if mdi_info['detected']:
        print("\n🛡️  MICROSOFT DEFENDER FOR IDENTITY (MDI)")
        print("-" * 40)
        print(f"  Status: ⚠️ MDI DETECTED - Advanced threat detection active")
        print(f"  Endpoint: {mdi_info['endpoint']}")
        print("\n  Red Team Implications:")
        for implication in mdi_info['redteam_implications']:
            print(f"    • {implication}")

    # OAuth/Application Risks
    if oauth_info['oauth_risks']:
        print("\n🎯 OAUTH & APPLICATION ATTACK SURFACE")
        print("-" * 40)

        if oauth_info['exposed_app_ids']:
            print(f"  Exposed App IDs: {len(oauth_info['exposed_app_ids'])} application(s)")
            for app_id in oauth_info['exposed_app_ids'][:3]:
                print(f"    • {app_id}")
            if len(oauth_info['exposed_app_ids']) > 3:
                print(f"    ... and {len(oauth_info['exposed_app_ids']) - 3} more")

        if oauth_info['admin_consent_endpoint']:
            print(f"\n  Admin Consent: ⚠️ Endpoint accessible")
            print(f"    URL: {oauth_info['admin_consent_endpoint']}")
            print(f"    Risk: Consent phishing attacks possible")

        print("\n  OAuth Attack Vectors:")
        for risk in oauth_info['oauth_risks']:
            print(f"    • {risk}")

    # Legacy Authentication
    if legacy_auth_info['risks']:
        print("\n⚠️  LEGACY AUTHENTICATION RISKS")
        print("-" * 40)

        if legacy_auth_info['exchange_legacy_enabled']:
            print("  Exchange Web Services: ⚠️ Accessible")
        if legacy_auth_info['activesync_enabled']:
            print("  ActiveSync: ⚠️ Accessible")

        print("\n  Security Risks:")
        for risk in legacy_auth_info['risks']:
            print(f"    • {risk}")

    # Azure Services
    azure_found = any(azure_services.values())
    if azure_found:
        print("\n☁️  AZURE INFRASTRUCTURE")
        print("-" * 40)

        if azure_services['app_services']:
            print(f"  App Services: {len(azure_services['app_services'])} found")
            for service in azure_services['app_services']:
                print(f"    • https://{service}")

        if azure_services['storage_accounts']:
            print(f"  Storage Accounts: {len(azure_services['storage_accounts'])} found")
            for storage in azure_services['storage_accounts']:
                print(f"    • https://{storage}")

        if azure_services['cdn_endpoints']:
            print(f"  CDN Endpoints: {len(azure_services['cdn_endpoints'])} found")
            for cdn in azure_services['cdn_endpoints']:
                print(f"    • https://{cdn}")

        if azure_services['key_vaults']:
            print(f"  Key Vaults: {len(azure_services['key_vaults'])} found")
            for vault in azure_services['key_vaults']:
                print(f"    • https://{vault}")

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

    # Categorize services for later use
    categorized_services = categorize_services(all_services)

    # Microsoft 365 and Azure AD reconnaissance (run first for context)
    m365_info = {'tenant_id': None, 'tenant_name': None, 'cloud_instance': None, 'tenant_region': None}
    federation_info = {'auth_type': None, 'is_federated': False, 'federation_brand': None, 'auth_url': None, 'cloud_instance': None}
    mdi_info = {'detected': False, 'endpoint': None, 'redteam_implications': []}
    oauth_info = {'oauth_risks': []}
    legacy_auth_info = {'risks': []}
    azure_services = {'app_services': [], 'storage_accounts': [], 'cdn_endpoints': [], 'key_vaults': []}

    if not args.no_m365:
        print(f"\n[*] Running Microsoft 365 & Azure AD reconnaissance...")
        m365_info = get_m365_tenant_info(args.domain)
        federation_info = check_azure_ad_federation(args.domain)
        mdi_info = check_mdi_instance(m365_info['tenant_name'])
        oauth_info = check_oauth_applications(m365_info['tenant_id'], args.domain)
        legacy_auth_info = check_legacy_auth(m365_info['tenant_id'], args.domain)
        azure_services = check_azure_services(args.domain)

    # Print organized summary
    print("\n" + "=" * 80)
    print(f"SECURITY ANALYSIS REPORT: {args.domain.upper()}")
    print("=" * 80)

    # 1. Target Overview (Tenant info if available)
    if m365_info['tenant_id'] or m365_info['tenant_name']:
        print("\n📋 TARGET OVERVIEW")
        print("-" * 40)
        print(f"  Domain: {args.domain}")
        if m365_info['tenant_name']:
            print(f"  Microsoft 365 Tenant: {m365_info['tenant_name']}.onmicrosoft.com")
        if m365_info['tenant_id']:
            print(f"  Tenant ID: {m365_info['tenant_id']}")
        if m365_info['cloud_instance']:
            print(f"  Cloud Instance: {m365_info['cloud_instance']}")
        if m365_info['tenant_region']:
            print(f"  Region: {m365_info['tenant_region']}")

    # 2. Microsoft 365 & Azure AD (if any data found)
    print_m365_azure_summary(args.domain, m365_info, federation_info, mdi_info, oauth_info, legacy_auth_info, azure_services)

    # 3. Email Security, Infrastructure, Services (consolidated)
    print_comprehensive_summary(args.domain, all_services, categorized_services, dns_info)

    # 4. Services & Integrations (moved to end for better flow)
    if args.verbose:
        print("\n" + "=" * 80)
        print("DETAILED SERVICE ENUMERATION")
        print("=" * 80)
        print_categorized_summary(categorized_services)
        print_verification_summary(dns_info)

    # Security report
    if args.security_report:
        print_security_summary(dns_info)

    # Export to JSON
    if args.output:
        export_json(all_services, dns_info, args.output)

    print(f"\n[*] Analysis complete!")

if __name__ == "__main__":
    main()

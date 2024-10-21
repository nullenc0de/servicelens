#!/usr/bin/env python3

import argparse
import dns.resolver
import xml.etree.ElementTree as ET
from urllib.request import urlopen, Request
from collections import defaultdict
import re

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
    txt_records = check_txt_records(subdomain)
    dmarc_records = check_dmarc(subdomain)
    spf_records = check_spf(subdomain)

    if verbose:
        print(f"TXT Records: {txt_records}")
        print(f"DMARC Records: {dmarc_records}")
        print(f"SPF Records: {spf_records}")

    services = extract_services(txt_records + dmarc_records + spf_records)

    if verbose:
        print(f"Subdomain appears to be {'valid' if services else 'invalid'}")

    return services

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
        'Email Services': ['outlook', 'gmail', 'yahoo', 'sendgrid', 'mailchimp', 'amazonses', 'zoho', 'postmark', 'mandrill', 'mailgun', 'sparkpost', 'protonmail', 'fastmail', 'sendpulse', 'sendinblue', 'mailjet', 'constantcontact', 'campaignmonitor', 'icontact', 'getresponse', 'aweber', 'activecampaign', 'drip', 'convertkit'],
        'Cloud Platforms': ['aws', 'azure', 'googlecloud', 'digitalocean', 'heroku', 'linode', 'vultr', 'rackspace', 'ibmcloud', 'oracle', 'onmicrosoft', 'protection.outlook', 'cloudflare', 'fastly', 'akamai', 'cdn77', 'maxcdn', 'stackpath', 'cloudflarenet', 'salesforce', 'force.com'],
        'Analytics and Surveys': ['google-analytics', 'googletagmanager', 'hotjar', 'mixpanel', 'kissmetrics', 'qualtrics', 'surveymonkey', 'typeform', 'segment', 'amplitude', 'heap', 'pendo', 'fullstory', 'optimizely', 'crazyegg', 'clicktale', 'mouseflow', 'luckyorange'],
        'Customer Support': ['zendesk', 'freshdesk', 'helpscout', 'intercom', 'drift', 'tawk', 'livechat', 'olark', 'uservoice', 'desk.com', 'gorgias', 'kustomer', 'gladly', 'frontapp', 'helpwise', 'kayako', 'zopim', 'snapengage'],
        'Security and Training': ['cloudflare', 'akamai', 'imperva', 'zscaler', 'proofpoint', 'mimecast', 'knowbe4', 'dmarcian', 'barracuda', 'symantec', 'mcafee', 'trend', 'sophos', 'kaspersky', 'bitdefender', 'malwarebytes', 'crowdstrike', 'carbonblack', 'cylance', 'sentinelone', 'fireeye', 'paloaltonetworks', 'fortinet'],
        'Marketing and CRM': ['hubspot', 'salesforce', 'marketo', 'eloqua', 'pardot', 'mailchimp', 'exacttarget', 'constantcontact', 'campaignmonitor', 'getresponse', 'activecampaign', 'drip', 'pipedrive', 'zoho', 'freshsales', 'insightly', 'nutshell', 'agilecrm', 'sugarcrm'],
        'Productivity and Collaboration': ['office365', 'gsuite', 'google.workspace', 'zoom', 'slack', 'dropbox', 'box', 'atlassian', 'asana', 'trello', 'basecamp', 'monday', 'notion', 'evernote', 'miro', 'airtable', 'clickup', 'wrike', 'teamwork', 'podio'],
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

def print_categorized_summary(categorized_services):
    print("\nCategorized Summary of Services:")
    print("================================")

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
            print()  # Add an extra newline for readability

def main():
    parser = argparse.ArgumentParser(description="Enumerates and validates Microsoft 365 domains")
    parser.add_argument("-d", "--domain", help="input domain name, example format: example.com", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    print(f"Enumerating Microsoft 365 domains for {args.domain}...")
    m365_domains = get_m365_domains(args.domain)

    all_services = defaultdict(set)

    if m365_domains:
        print("Found the following Microsoft 365 domains:")
        for domain in m365_domains:
            print(domain)
            services = validate_subdomain(domain, args.verbose)
            all_services[domain].update(services)
    else:
        print("No Microsoft 365 domains found.")

    # Also validate the original domain
    services = validate_subdomain(args.domain, args.verbose)
    all_services[args.domain].update(services)

    if args.verbose:
        print("\nDetailed Summary of services used:")
        for domain, services in all_services.items():
            print(f"\n{domain}:")
            for service in sorted(services):
                print(f"  - {service}")

    categorized_services = categorize_services(all_services)
    print_categorized_summary(categorized_services)

if __name__ == "__main__":
    main()

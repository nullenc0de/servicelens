# Domain Service Analyzer

## Description

Domain Service Analyzer is a Python script that enumerates Microsoft 365 domains for a given domain and analyzes the services associated with it. It checks DNS records (TXT, DMARC, SPF) to identify various services used by the domain and its subdomains, categorizing them into different service types such as Email Services, Cloud Platforms, Analytics, and more.

## Features

- Enumerates Microsoft 365 domains associated with the input domain
- Validates subdomains and extracts services from DNS records
- Categorizes services into predefined categories
- Provides a detailed, categorized summary of services found
- Verbose mode for more detailed output

## Requirements

- Python 3.6+
- dnspython library

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/domain-service-analyzer.git
   cd domain-service-analyzer
   ```

2. Install the required dependencies:
   ```
   pip install dnspython
   ```

## Usage

Run the script with a domain name:

```
python domain_service_analyzer.py -d example.com
```

For verbose output, add the `-v` flag:

```
python domain_service_analyzer.py -d example.com -v
```

## Output

The script provides a categorized summary of services, including:

- Email Services
- Cloud Platforms
- Analytics and Surveys
- Customer Support
- Security and Training
- Marketing and CRM
- Productivity and Collaboration
- Development and Version Control
- Content Delivery and Hosting
- Payment and Financial Services
- Uncategorized Services

For each service, it shows which domain or subdomain it was associated with.

Example Output:

![image](https://github.com/user-attachments/assets/3b8d165b-da12-46d8-8cab-f25f1db7a76e)


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and informational purposes only. Ensure you have permission to scan domains that you do not own. The authors are not responsible for any misuse or damage caused by this program.

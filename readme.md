# JohnDCyber_SPF_DKIM_DMARC_SCANNER

A **quick and dirty** Python tool for discovering domains that are missing or misconfiguring **SPF**, **DKIM**, and **DMARC** records. Security teams, IT administrators, and researchers can use this tool to quickly **locate insecure domains** and **reduce spoofing risks** in their environments.

Now enhanced with:
- **pandas-based analytics**  
- **HTML reporting** with a **dark purple** theme  
- **Searchable table** for quick filtering  
- **Timestamped** CSV and HTML output  

---

## Table of Contents

- [Overview](#overview)  
- [Why Use This Tool?](#why-use-this-tool)  
- [Key Features](#key-features)  
- [Usage](#usage)  
- [Flag Usage Explanation](#flag-usage-explanation)  
- [Disclaimer](#disclaimer)  

---

## Overview

**JohnDCyber_SPF_DKIM_DMARC_SCANNER** performs DNS record lookups across a list of domains to check for valid **SPF**, **DKIM**, and **DMARC** configurations.

- **SPF** helps prevent unauthorized senders from using your domain.  
- **DKIM** ensures emails are cryptographically signed.  
- **DMARC** aligns SPF/DKIM policies, mitigating spoofed emails.  

If these records are missing or misconfigured, attackers can spoof emails more easily. This script flags such vulnerabilities so you can act quickly.
<img width="644" alt="image" src="https://github.com/user-attachments/assets/e50fd1c8-1d32-4338-a2b4-6d56654fe1ec" />

---

## Why Use This Tool?

1. **Quick & Dirty**: Easily set up; minimal friction.  
2. **Free & Effective**: No licensing cost, no external dependencies (beyond Python + a few libraries).  
3. **Attack Footprint Discovery**: Identify insecure or unmonitored domains that can be prime targets for phishing.  
4. **Multi-Threaded**: Scans large domain lists efficiently using `ThreadPoolExecutor`.  
5. **pandas Analytics + HTML**: Rich statistics, a user-friendly web report, and a JavaScript search bar.

---

## Key Features

- **SPF Check**: Looks for `v=spf1` + `all` in TXT records.  
- **DMARC Check**: Verifies `v=DMARC1` and a policy (`p=none|quarantine|reject`).  
- **DKIM Check**: Tries common selectors (e.g., `default._domainkey`, `selector1._domainkey`) for a `v=DKIM1` key.  
- **Spoofing Vulnerability**: Flags domain as “Yes” if SPF or DMARC fails.  
- **Subdomain Takeover Check**: If the domain returns `NXDOMAIN`, it might be vulnerable to takeover.  
- **CSV + HTML Output**:  
  - **Timestamped** so you don’t overwrite older reports.  
  - **HTML** includes a dark purple theme, a summary of results, scan duration, and search functionality.  
- **pandas** Integration:  
  - The results are handled via a DataFrame for easy manipulation and robust analytics.  

---

## Usage

1. **Install Requirements**:  
   ```bash
   pip install dnspython pandas

# Usage & Configuration
**(Requires Python 3.x)**
## Create a Domain List

Prepare a file (e.g., `domains.txt`) containing one domain per line:

```plaintext
example.com
subdomain.example.com
testdomain.net
mydomain.co
...
```
# Usage & Script Details

## Basic Run

```bash
python3 JohnDCyber_SPF_DKIM_DMARC_SCANNER.py
```
## By default, the script:

- **Reads** from domains.txt
- **Outputs** a CSV named domain_check_results_<timestamp>.csv
- **Outputs** an HTML report named domain_check_results_<timestamp>.html

# Advanced Usage
```bash
python3 JohnDCyber_SPF_DKIM_DMARC_SCANNER.py \
    --input-file mydomains.txt \
    --output-csv results.csv \
    --output-html results.html \
    --threads 20 \
    --nameserver 8.8.8.8 \
    --timeout 5 \
    --dkim-selectors default mail selector1
```

# Flag Usage Explanation
- input-file / -i
Path to your domain list (one domain per line).
- output-csv
Base name for the CSV output file (timestamp appended).

- output-html
Base name for the HTML output file (timestamp appended).

- threads / -t
Number of parallel threads for concurrent DNS lookups.

- nameserver
Custom DNS server (e.g., 8.8.8.8).

- timeout
DNS resolution timeout (in seconds).

- dkim-selectors
Space-separated list of DKIM selectors to check.

# Disclaimer 
This is a quick & dirty tool. It does not validate every possible nuance of SPF, DKIM, or DMARC records.
For production or enterprise usage, consider specialized libraries:
pyspf for detailed SPF parsing.
dkimpy for DKIM cryptographic checks.
Always test responsibly on domains you own or have permission to scan.
No guarantees are provided for accuracy or completeness.
Happy scanning! This free script is super effective for discovering your attack footprint and quickly mitigating spoofing or subdomain takeover risks.

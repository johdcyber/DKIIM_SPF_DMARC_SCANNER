#!/usr/bin/env python3

import csv
import sys
import argparse
import dns.resolver
import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd

BANNER = r"""
  (_) ___ | |__  _ __ |  _ \ / ___|   _| |__   ___ _ __ 
   | |/ _ \| '_ \| '_ \| | | | |  | | | | '_ \ / _ \ '__|
   | | (_) | | | | | | | |_| | |__| |_| | |_) |  __/ |   
  _/ |\___/|_| |_|_| |_|____/ \____\__, |_.__/ \___|_|                    
   -----------------------------------------------------------
      SPF   |   DKIM   |   DMARC   SCANNER
   -----------------------------------------------------------

   JohnDCyber_SPF_DKIM_DMARC_SCANNER
"""

def validate_spf(record_content: str) -> bool:
    """
    A simple heuristic to check if a TXT record looks like a valid SPF record.
    Looks for 'v=spf1' and includes 'all' directive.
    """
    record_lower = record_content.lower()
    return ("v=spf1" in record_lower) and ("all" in record_lower)

def validate_dmarc(record_content: str) -> bool:
    """
    Basic DMARC validation:
      - Must contain 'v=DMARC1'
      - Must have p=none/quarantine/reject
    """
    lower = record_content.lower()
    return (
        "v=dmarc1" in lower and
        any(pol in lower for pol in ['p=none', 'p=quarantine', 'p=reject'])
    )

def validate_dkim(record_content: str) -> bool:
    """
    Simple DKIM validation:
      - Contains 'v=DKIM1'
      - Contains 'p=' (public key)
    """
    lower = record_content.lower()
    return ("v=dkim1" in lower) and ("p=" in lower)

def check_dns_records(domain: str, known_dkim_selectors=None, nameserver=None, timeout=3.0) -> dict:
    """
    Check DNS records for SPF, DKIM, DMARC, plus a subdomain takeover heuristic.
    """
    results = {
        'domain': domain,
        'SPF': 'Fail',
        'DKIM': 'Fail',
        'DMARC': 'Fail',
        'Vulnerable to Spoofing': 'Yes',
        'Potential Subdomain Takeover': 'Unknown'
    }

    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.lifetime = timeout

    # 1. Check SPF
    try:
        spf_answers = resolver.resolve(domain, 'TXT')
        for rdata in spf_answers:
            combined_text = "".join(part.decode() for part in rdata.strings)
            if validate_spf(combined_text):
                results['SPF'] = 'Pass'
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        pass

    # 2. Check DMARC
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in dmarc_answers:
            combined_text = "".join(part.decode() for part in rdata.strings)
            if validate_dmarc(combined_text):
                results['DMARC'] = 'Pass'
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        pass

    # 3. Check DKIM
    if not known_dkim_selectors:
        results['DKIM'] = 'Unknown'
    else:
        for selector in known_dkim_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                dkim_answers = resolver.resolve(dkim_domain, 'TXT')
                for rdata in dkim_answers:
                    combined_text = "".join(part.decode() for part in rdata.strings)
                    if validate_dkim(combined_text):
                        results['DKIM'] = 'Pass'
                        break
                if results['DKIM'] == 'Pass':
                    break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass

    # 4. Determine vulnerability to spoofing
    if results['SPF'] == 'Pass' and results['DMARC'] == 'Pass':
        results['Vulnerable to Spoofing'] = 'No'

    # 5. Subdomain takeover heuristic (NXDOMAIN check)
    try:
        resolver.resolve(domain, 'A')
        results['Potential Subdomain Takeover'] = 'No'
    except dns.resolver.NXDOMAIN:
        results['Potential Subdomain Takeover'] = 'Yes'
    except (dns.resolver.NoAnswer, dns.exception.DNSException):
        pass

    return results

def worker(domain, known_dkim_selectors, nameserver, timeout):
    """
    Worker function for the ThreadPoolExecutor.
    """
    try:
        return check_dns_records(domain, known_dkim_selectors, nameserver, timeout)
    except Exception as e:
        print(f"[ERROR] {domain}: {e}")
        return {
            'domain': domain,
            'SPF': 'Error',
            'DKIM': 'Error',
            'DMARC': 'Error',
            'Vulnerable to Spoofing': 'Error',
            'Potential Subdomain Takeover': 'Error'
        }

def generate_csv(df: pd.DataFrame, base_output_csv: str) -> str:
    """
    Writes the DataFrame to a timestamped CSV.
    Returns the generated filename.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_csv = f"{base_output_csv.rsplit('.', 1)[0]}_{timestamp}.csv"
    df.to_csv(output_csv, index=False)
    return output_csv

def generate_html(df: pd.DataFrame, base_output_html: str, start_time: float, end_time: float) -> str:
    """
    Generates a single HTML file with:
      - Dark purple theme
      - Summary analytics (via pandas)
      - A searchable table (via a small JavaScript filter)
    """
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_html = f"{base_output_html.rsplit('.', 1)[0]}_{timestamp_str}.html"

    # ---- Calculate analytics using pandas
    total_domains = len(df)
    vulnerable_count = (df['Vulnerable to Spoofing'] == 'Yes').sum()
    sub_takeover_count = (df['Potential Subdomain Takeover'] == 'Yes').sum()
    scan_duration = end_time - start_time

    # We can do additional robust analytics if desired, e.g.:
    # group by SPF/DMARC pass/fail, etc. For now, we keep it simple.

    # Generate the main data table as HTML
    # We'll add an id="resultsTable" to use a simple JS search filter
    table_html = df.to_html(
        index=False,
        classes='results-table',
        table_id='resultsTable',
        border=0
    )

    # Simple JavaScript for searching the table by domain or any cell
    search_script = """
    <script>
    function searchTable() {
      var input, filter, table, tr, td, i, j, txtValue;
      input = document.getElementById("searchInput");
      filter = input.value.toUpperCase();
      table = document.getElementById("resultsTable");
      tr = table.getElementsByTagName("tr");
      for (i = 1; i < tr.length; i++) {
        tr[i].style.display = "none";
        td = tr[i].getElementsByTagName("td");
        for (j = 0; j < td.length; j++) {
          if (td[j]) {
            txtValue = td[j].textContent || td[j].innerText;
            if (txtValue.toUpperCase().indexOf(filter) > -1) {
              tr[i].style.display = "";
              break;
            }
          }
        }
      }
    }
    </script>
    """

    # Minimal dark purple styling
    css_style = """
    body {
        background-color: #210A32; /* Dark purple */
        color: #E6D3F2;
        font-family: "Consolas", monospace;
        margin: 20px;
    }
    h1, h2 {
        text-align: center;
        color: #DABFFF;
    }
    .analytics, .timestamp {
        margin: 20px auto;
        max-width: 600px;
        background-color: #2A0C3F;
        padding: 15px;
        border-radius: 5px;
    }
    .analytics h2, .timestamp h2 {
        margin-top: 0;
    }
    .search-box {
        text-align: center;
        margin: 20px;
    }
    input[type="text"] {
        padding: 8px;
        font-size: 16px;
        width: 50%;
        border: 1px solid #9C6CD1;
        border-radius: 4px;
        background-color: #2F0B44;
        color: #E6D3F2;
    }
    table.results-table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
    }
    table.results-table th, table.results-table td {
        border: 1px solid #9C6CD1;
        padding: 8px;
        text-align: left;
    }
    table.results-table th {
        background: #3C1053;
        color: #EEE;
    }
    table.results-table tr:nth-child(even) {
        background: #2F0B44;
    }
    """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SPF_DKIM_DMARC_SCANNER Report</title>
    <style>{css_style}</style>
</head>
<body>

<h1>JohnDCyber SPF_DKIM_DMARC_SCANNER - Report</h1>

<div class="analytics">
  <h2>Analytics Summary</h2>
  <ul>
    <li><strong>Total Domains Scanned:</strong> {total_domains}</li>
    <li><strong>Vulnerable to Spoofing (Yes):</strong> {vulnerable_count}</li>
    <li><strong>Potential Subdomain Takeovers (Yes):</strong> {sub_takeover_count}</li>
    <li><strong>Scan Duration (seconds):</strong> {scan_duration:.2f}</li>
  </ul>
</div>

<div class="search-box">
    <input type="text" id="searchInput" onkeyup="searchTable()" placeholder="Search by any column...">
</div>

{table_html}

<div class="timestamp">
  <h2>Report generated at: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</h2>
</div>

{search_script}
</body>
</html>
"""

    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return output_html

def main():
    print(BANNER)  # Banner in console only

    parser = argparse.ArgumentParser(
        description="Quick & Dirty SPF, DKIM, DMARC scanner with pandas-based analytics and a searchable HTML table."
    )
    parser.add_argument(
        '--input-file', '-i', default='domains.txt',
        help='Path to file with domain names, one per line.'
    )
    parser.add_argument(
        '--output-csv', default='domain_check_results.csv',
        help='Base name for CSV output (timestamp appended).'
    )
    parser.add_argument(
        '--output-html', default='domain_check_results.html',
        help='Base name for HTML output (timestamp appended).'
    )
    parser.add_argument(
        '--threads', '-t', type=int, default=10,
        help='Number of threads for concurrent DNS lookups.'
    )
    parser.add_argument(
        '--nameserver', default=None,
        help='Optional custom DNS nameserver, e.g., 8.8.8.8'
    )
    parser.add_argument(
        '--timeout', type=float, default=3.0,
        help='DNS query timeout in seconds.'
    )
    parser.add_argument(
        '--dkim-selectors', nargs='*',
        default=['default', 'selector1', 'selector2', 'mail'],
        help='List of DKIM selectors to try. If empty, DKIM=Unknown.'
    )

    args = parser.parse_args()

    # Read domain list
    try:
        with open(args.input_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {args.input_file}")
        sys.exit(1)

    if not domains:
        print("[ERROR] No domains found in the input file.")
        sys.exit(1)

    # Start timing
    start_time = time.time()

    # Collect results
    results_list = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_domain = {
            executor.submit(
                worker,
                domain,
                args.dkim_selectors,
                args.nameserver,
                args.timeout
            ): domain
            for domain in domains
        }

        total_count = len(domains)
        completed_count = 0
        for future in as_completed(future_to_domain):
            completed_count += 1
            domain = future_to_domain[future]
            try:
                result = future.result()
                results_list.append(result)
                print(f"[INFO] Checked {domain} - {completed_count}/{total_count} "
                      f"({(completed_count / total_count)*100:.2f}%)")
            except Exception as e:
                print(f"[ERROR] {domain}: {e}")

    # End timing
    end_time = time.time()

    # Convert results_list to a pandas DataFrame
    df = pd.DataFrame(results_list)

    # Output to CSV
    csv_file = generate_csv(df, args.output_csv)
    # Output to HTML (with analytics)
    html_file = generate_html(df, args.output_html, start_time, end_time)

    print(f"\n[INFO] Scan Complete!\n"
          f"      CSV results -> {csv_file}\n"
          f"      HTML results -> {html_file}\n")

if __name__ == '__main__':
    main()

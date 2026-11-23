# Webgeek DNS, SSL & Email Security Scanner (WordPress Plugin)

A lightweight, zero-dependency WordPress plugin for real-time **DNS, SSL/TLS, and Email Security (SPF, DKIM, DMARC)** diagnostics. Built with clean PHP and Vanilla JS for minimal server overhead.

👉 **Live Demo:** [DNS, SSL & Email Security Scanner on webgeek.com.hr](https://webgeek.com.hr/blog/besplatni-dns-ssl-i-email-sigurnosni-skener/)

## Features
- **DNS Lookup:** Checks `A`, `AAAA`, `MX`, `NS`, and `TXT` records.
- **SSL/TLS Inspection:** Verifies certificate validity, issuer, and expiration date.
- **Email Security Audit:** Analyzes `SPF`, `DKIM`, and `DMARC` records to help prevent spoofing and improve deliverability.
- **Zero Dependencies:** Pure PHP and Vanilla JavaScript/CSS — no external libraries or bloated frameworks.
- **Conditional Asset Loading:** CSS and JS are enqueued only on pages containing the plugin shortcode.

## Installation
1. Download or clone this repository into `/wp-content/plugins/wg-dns-scanner/` (or zip it and upload via **Plugins → Add New → Upload Plugin**).
2. Activate the plugin in your WordPress dashboard.
3. Embed the scanner on any page or post using the plugin shortcode.

## Author
Developed by **Webgeek** — more free web & SEO tools at [webgeek.com.hr](https://webgeek.com.hr).

## License
Distributed under the license specified in the `LICENSE` file.
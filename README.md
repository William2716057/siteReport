# URL Scanner using VirusTotal API

This is a Python script that allows you to scan URLs using the VirusTotal API for potential threats. It submits a URL for scanning and retrieves the scan report.

## Prerequisites

Before using this script, ensure you have the following:

- Python 3 installed on your system.
- An API key from VirusTotal. You can obtain one by signing up for an account on [VirusTotal](https://www.virustotal.com).

## Installation

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/William2716057/siteReport.git

2. Install the required Python packages:
  ``` bash
  pip install -r requirements.txt
  ```
## Usage
1. Run the script:
```bash
python  virusTotalReportAPI.py
```
3. Follow the prompts to enter the URL you want to scan and your VirusTotal API key.
4. After submitting the URL for scanning, the script will provide you with a scan ID. Press Enter to retrieve the scan report.

## Features
- Submit URLs for scanning.
- Retrieve scan reports.
- Saves scan results to a text file for further analysis.

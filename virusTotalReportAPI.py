import requests

def scanURL(url, api_key):
    params = {'apikey': api_key, 'url': url}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            print("URL successfully submitted for scanning.")
            return json_response['scan_id']
        else:
            print("Failed to submit URL for scanning. Error message:", json_response['verbose_msg'])
    else:
        print("Failed to submit URL for scanning. HTTP Error:", response.status_code)

def retrieve_report(scan_id, api_key):
    params = {'apikey': api_key, 'resource': scan_id}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            with open('report.txt', 'w') as report_file:
                report_file.write("Scan results for URL: {}\n".format(json_response['url']))
                report_file.write("Scan date: {}\n".format(json_response['scan_date']))
                report_file.write("Positives: {}\n".format(json_response['positives']))
                report_file.write("Total scans: {}\n".format(json_response['total']))
                report_file.write("Scan results:\n")
                for scanner, result in json_response['scans'].items():
                    report_file.write("\t{}: {}\n".format(scanner, result['result']))
            print("Scan results written to report.txt")
        else:
            print("Failed to retrieve scan report. Error message:", json_response['verbose_msg'])
    else:
        print("Failed to retrieve scan report. HTTP Error:", response.status_code)

if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    api_key = input("Enter your VirusTotal API key: ")

    scan_id = scanURL(url, api_key)
    if scan_id:
        print("Scan ID:", scan_id)
        input("Press Enter to retrieve the scan report...")
        retrieve_report(scan_id, api_key)

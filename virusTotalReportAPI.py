import requests

def scanURL(url, api_key):
    params = {'apikey': api_key, 'url': url}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
    #check if url reachable
    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            print("URL successfully submitted.")
            return json_response['scan_id']
        else:
            print("Failed to submit URL. Error message:", json_response['verbose_msg'])
    else:
        print("Failed to submit URL. HTTP Error:", response.status_code)
        #function to get and write report
def retrieveReport(scan_id, api_key):
    params = {'apikey': api_key, 'resource': scan_id}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            with open('report.txt', 'w') as reportFile:
                reportFile.write("Scan results for URL: {}\n".format(json_response['url']))
                reportFile.write("Scan date: {}\n".format(json_response['scan_date']))
                reportFile.write("Positives: {}\n".format(json_response['positives']))
                reportFile.write("Total scans: {}\n".format(json_response['total']))
                reportFile.write("Scan results:\n")
                for scanner, result in json_response['scans'].items():
                    reportFile.write("\t{}: {}\n".format(scanner, result['result']))
            print("Results saved to report.txt")
        else:
            print("Could not retrieve scan report. Error message:", json_response['verbose_msg'])
    else:
        print("Failed to retrieve scan report. HTTP Error:", response.status_code)

if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    APIkey = input("Enter API key: ")

    scanID = scanURL(url, APIkey)
    if scanID:
        print("Scan ID:", scanID)
        input("Press Enter to retrieve the scan report...")
        retrieveReport(scanID, APIkey)

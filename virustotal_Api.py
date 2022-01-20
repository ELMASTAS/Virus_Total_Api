import requests
import time
import json
dosya = open('url_file.txt', 'r')
for site in dosya:
    api_key = 'API KEY'
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    time.sleep(5)
    params = {'apikey': api_key, 'resource': site}
    response = requests.get(url, params=params)
    response_json = json.loads(response.content)
    scanner = response_json['scans']
    scanner_count = 1
    for i in scanner:
        print(scanner_count, " : ", i, " - ", scanner[i], '\n')
        scanner_count = scanner_count + 1
    if response_json['positives'] <= 0:

        vt = open('NOT_MALICIOUS.txt', 'a+')
        vt.write(str(site)) and vt.write('-\tNOT MALICIOUS\n')

    elif 1 >= response_json['positives'] >= 3:

        vt = open('MAYBE_MALICIOUS.txt', 'a+')
        vt.write(str(site)) and vt.write('-\tMAYBE MALICIOUS\n')

    elif response_json['positives'] >= 4:
        vt = open('MALICIOUS.txt', 'a+')
        vt.write(str(site)) and vt.write('-\tMALICIOUS\n')
    else:
        print('url not found')

    time.sleep(25)
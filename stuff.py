import requests
import os
import re
import time
import traceback
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Domain_Recon(object):


    def GET_CTFR(self):
        dr.subdomains = []
        domain = input('Input Domain\n')

        print('Querying certspotter database')
        get_subdomains = requests.get("https://api.certspotter.com/v1/issuances?domain="+domain+'&include_subdomains=true&expand=dns_names')
        subdomain_page = get_subdomains.text.split('"dns_names":[')
        print('Parsing subdomains')
        for page in subdomain_page[1:]:
            page_list = page.split('],')[0].split(',')
            for page2 in page_list:
                dr.subdomains.append(page2.split('"')[1])

        print(list(set(dr.subdomains)))

    def shodan_api(self):
        shodan_key = '&key=putAPIkeyHere'
        print('Processing subdomains to Shodan'
        for subdomain in list(set(dr.subdomains)):
            time.sleep(1)
            try:
                print('Resolving '+subdomain)
                host_resolve_shodan = requests.get('https://api.shodan.io/dns/resolve?hostnames='+subdomain+shodan_key, verify = False )
                print('IP FOUND! '+host_resolve_shodan.text)

                try:
                    resolved_IP = host_resolve_shodan.text.split(':')[1].split('"')[1]
                except:
                    print('Null IP')
                try:
                    os.makedirs('target/'+time.strftime("%Y-%m-%d")+'/'+subdomain)
                except:
                    print (traceback.print_exc())
                
                print('Getting Shodan info')
                      
                dr.shodan_results = requests.get('https://api.shodan.io/shodan/host/'+resolved_IP+shodan_key, verify = False).text
                shodan_lines = dr.shodan_results.split(',')



                if dr.shodan_results != '{"error": "No information available for that IP."}':
                    with open('target/'+time.strftime("%Y-%m-%d")+'/'+subdomain+'/info.csv','w') as ifile:
                        for line in shodan_lines:
                            ifile.write(line+'\n')
                    regex = re.compile(r'(CVE-[0-9]{4}-[0-9]{4})')
                    vulns = regex.findall(dr.shodan_results)
                    #input(vulns)
                    try:

                        for vuln in vulns:
                            vuln_check = requests.get("http://cve.circl.lu/api/cve/"+vuln, verify = False)

                            with open('target/'+time.strftime("%Y-%m-%d")+'/'+subdomain+'/'+vuln+'.txt','w') as ifile2:
                                ifile2.write(vuln_check.text)
                    except:
                        traceback.print_exc()
                else:
                    print('Removing useless stuff')
                    
                    try:
                        os.remove('target/'+time.strftime("%Y-%m-%d")+'/'+subdomain+'/info.csv')
                    except:
                        traceback.print_exc()                    
                for i in os.listdir("target/"+time.strftime("%Y-%m-%d")):
                    try:
                        os.rmdir("target/"+time.strftime("%Y-%m-%d")+'/'+i)
                    except:
                        pass
            except:
                traceback.print_exc()
                print('oops :(')
                #input()

if __name__ == '__main__':
    dr = Domain_Recon()
    dr.GET_CTFR()
    dr.shodan_api()

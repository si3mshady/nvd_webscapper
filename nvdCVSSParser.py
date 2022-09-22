import requests
from bs4 import BeautifulSoup as soup
import pandas as pd


class NVD:
    def __init__(self, cve=''):
        self.nvd_url_base  = 'https://nvd.nist.gov/vuln/detail/' 
        self.cve = cve
        self.html_soup = self.make_html_soup()

    def make_html_soup(self: soup) -> soup:
        if self.cve == None:
            print('CVE not defined')
            return 
        result = requests.get(self.nvd_url_base + self.cve)
        if result.status_code == 200:
            html = result.content.decode()
            
            return soup(html, 'html.parser')
        else:
            print(result.status_code)
            return result.status_code

    def get_cvss_version_3_basescore(self):
        base_score_id = 'Cvss3NistCalculatorAnchor'
        result = self.html_soup.find(id=base_score_id)
        return result.text

    def get_cvss_version_2_basescore(self):
        base_score_id = 'Cvss2CalculatorAnchor'
        result = self.html_soup.find(id=base_score_id)
        return result.text

    def get_cvss_version_3_vector(self):
         result = self.html_soup.find('span',{'class':'tooltipCvss3NistMetrics'})
         return result.text

    def get_cvss_version_2_vector(self):
         result = self.html_soup.find('span',{'class':'tooltipCvss2NistMetrics'})
         return result.text


    def get_vuln_description(self):
        if self.cve == None:
            print('CVE not defined')
            return
        
        result = self.html_soup.find('p',{'data-testid':'vuln-description'})
        return result.text

    def get_hidden_information(self):
        result = self.html_soup.find(id='nistV3MetricHidden')
        print(result)


    def create_dataframe(self):
        v3_array_data = [self.cve,self.get_cvss_version_3_basescore(),self.get_cvss_version_3_vector()]
        v2_array_data = [self.cve,self.get_cvss_version_2_basescore(),self.get_cvss_version_2_vector()]
        structure = {"CVSS_V3":v3_array_data , "CVSS_V2":v2_array_data}
        df = pd.DataFrame(data=structure)
        return df
         
    
if __name__ == "__main__":
    # https://www.cvedetails.com/vulnerability-list/year-2020/vulnerabilities.html
    vuln_list = ["CVE-2020-35931","CVE-2020-35930","CVE-2020-35924","CVE-2020-35918","CVE-2020-35922"]
    try:
        [print(v.create_dataframe()) for v in [NVD(vuln) for vuln in vuln_list if vuln] ]
    except Exception as e:
        pass

#Elliott Arnold fetching CVSS Scores from NVD website 
#Trellix 9-21-22 SRE

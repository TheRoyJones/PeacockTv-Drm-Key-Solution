import os
import sys
import requests
import json
import time
import hmac
import base64
import hashlib
import signal
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
import pwinput
from datetime import datetime, timedelta

#Config
MyWVD = './WVD.wvd'

platform = 'ANDROIDTV'
device = 'TV'

def ascii_clear():
    os.system('cls||clear')
    print("""
                                                                                                      @@@@                     
                                                                                                      @@@@                     
                                                                                                      @@@@                     
                                                                                                      @@@@                     
  &@@@@@@@@@@@      @@@@@@@@@@@@     @@@@@@@@@@@@@@,   @@@@@@@@@@@@   (@@@@@@@@@@@      @@@@@@@@@@@@  @@@@   ,@@@@(            
 @@@@      @@@@@  @@@@@      @@@@   @@@@      @@@@@, ,@@@@      @@   @@@@      (@@@@  #@@@@      @@   @@@@ @@@@@               
@@@@        *@@@  @@@@@@@@@@@@@@@@ @@@@        *@@@, @@@@           @@@@         @@@* @@@@            @@@@@@@@                 
@@@@        @@@@  @@@@             @@@@        @@@@, @@@@           %@@@*       @@@@  @@@@            @@@@@, @@@@              
@@@@     (@@@@@    @@@@@@ .@@@@@    @@@@@@, %@@@@@@,  @@@@@@  &@@@@% (@@@@@, #@@@@@    @@@@@@  @@@@@/ @@@@    %@@@@            
@@@@@@@@@@@@@        %@@@@@@@@.        @@@@@@@@.@@@,    .@@@@@@@@(      @@@@@@@@@        /@@@@@@@@*   @@@@      @@@@@          
@@@@ @@                                                                                                                        
@@@@                                                                                                                           
@@@@                                                                                                                           
@@@@                                                                                                                                      
             
                                               Key Solution                                      
                                               TAJLN 2023  
                                               
""")

def signal_handler(sig, frame):
    print('\nBye :)')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def do_cdm(manifest_url, license_url):
    manifest_url = manifest_url.split('?')[0]

    manifest = requests.get(manifest_url)
        
    if manifest.status_code != 200:
        print(title)
        print('Invalid manifest found')
        return
    
    pssh = PSSH(BeautifulSoup(manifest.content, features="xml").findAll('cenc:pssh')[1].text)

    device = Device.load(MyWVD)
    cdm = Cdm.from_device(device)
    session_id = cdm.open()
    challenge = cdm.get_license_challenge(session_id, pssh)

    licence = requests.post(license_url, data=challenge)
    licence.raise_for_status()
    cdm.parse_license(session_id, licence.content)

    print('   - Manifest url: ' + manifest_url)

    print('   - DRM Keys:')
    for key in cdm.get_keys(session_id):
        if key.type != 'SIGNING':
            print(f"      {key.kid.hex}:{key.key.hex()}")

    print('')

    cdm.close(session_id)


def calculate_signature(method, url, headers, payload, timestamp=None):
    app_id = 'NBCU-ANDROID-v3'
    signature_key = bytearray('JuLQgyFz9n89D9pxcN6ZWZXKWfgj2PNBUb32zybj', 'utf-8')
    sig_version = '1.0'

    if not timestamp:
      timestamp = int(time.time())

    if url.startswith('http'):
      parsed_url = urlparse(url)
      path = parsed_url.path
    else:
      path = url

    #print('path: {}'.format(path))

    text_headers = ''
    for key in sorted(headers.keys()):
      if key.lower().startswith('x-skyott'):
        text_headers += key + ': ' + headers[key] + '\n'
    #print(text_headers)
    headers_md5 = hashlib.md5(text_headers.encode()).hexdigest()
    #print(headers_md5) peaCOCK

    if sys.version_info[0] > 2 and isinstance(payload, str):
      payload = payload.encode('utf-8')
    payload_md5 = hashlib.md5(payload).hexdigest()

    to_hash = ('{method}\n{path}\n{response_code}\n{app_id}\n{version}\n{headers_md5}\n'
              '{timestamp}\n{payload_md5}\n').format(method=method, path=path,
                response_code='', app_id=app_id, version=sig_version,
                headers_md5=headers_md5, timestamp=timestamp, payload_md5=payload_md5)
    #print(to_hash)

    hashed = hmac.new(signature_key, to_hash.encode('utf8'), hashlib.sha1).digest()
    signature = base64.b64encode(hashed).decode('utf8')

    return 'SkyOTT client="{}",signature="{}",timestamp="{}",version="{}"'.format(app_id, signature, timestamp, sig_version)

def vod_request(provider_variant_id, user_token):
    url = 'https://ovp.peacocktv.com/video/playouts/vod'

    headers = {
        'accept': 'application/vnd.playvod.v1+json',
        'content-type': 'application/vnd.playvod.v1+json',
        'x-skyott-activeterritory': country_code,
        'x-skyott-coppa': 'false',
        'x-skyott-device': device,
        'x-skyott-pinoverride': 'false',
        'x-skyott-platform': platform,
        'x-skyott-proposition': 'NBCUOTT',
        'x-skyott-provider': 'NBCU',
        'x-skyott-territory': country_code,
        'x-skyott-usertoken': user_token
    }

    data = {
      "device": {
        "capabilities": [
                #H265 EAC3
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H265",
                  "acodec": "EAC3",
                  "container": "TS"
                },
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H265",
                  "acodec": "EAC3",
                  "container": "ISOBMFF"
                },
                {
                  "container": "MP4",
                  "vcodec": "H265",
                  "acodec": "EAC3",
                  "protection": "WIDEVINE",
                  "transport": "DASH"
                },

                #H264 EAC3
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H264",
                  "acodec": "EAC3",
                  "container": "TS"
                },
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H264",
                  "acodec": "EAC3",
                  "container": "ISOBMFF"
                },
                {
                  "container": "MP4",
                  "vcodec": "H264",
                  "acodec": "EAC3",
                  "protection": "WIDEVINE",
                  "transport": "DASH"
                },

                #H265 AAC
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H265",
                  "acodec": "AAC",
                  "container": "TS"
                },
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H265",
                  "acodec": "AAC",
                  "container": "ISOBMFF"
                },
                {
                  "container": "MP4",
                  "vcodec": "H265",
                  "acodec": "AAC",
                  "protection": "WIDEVINE",
                  "transport": "DASH"
                },

                #H264 AAC
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H264",
                  "acodec": "AAC",
                  "container": "TS"
                },
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H264",
                  "acodec": "AAC",
                  "container": "ISOBMFF"
                },
                {
                  "container": "MP4",
                  "vcodec": "H264",
                  "acodec": "AAC",
                  "protection": "WIDEVINE",
                  "transport": "DASH"
                },
            ],
            "model": "Nvidia Shield Android TV",
            "maxVideoFormat": 'UHD',
            "hdcpEnabled": 'false',
            "supportedColourSpaces": [
              "DV",
              "HDR10",
              "SDR"
            ]
      },
      "providerVariantId": provider_variant_id,
      "parentalControlPin": 'null',
      "personaParentalControlRating": "9"
    }
    
    data = json.dumps(data)
    headers['x-sky-signature'] = calculate_signature('POST', url, headers, data)

    response = json.loads(requests.post(url, headers=headers, data=data).content)
    
    try:
        manifest_url = response['asset']['endpoints'][0]['url']
        license_url = response['protection']['licenceAcquisitionUrl']
    except:
        print('Vod request failed')
        print(json.dumps(response))
        quit()
        
    do_cdm(manifest_url, license_url)

def live_request(service_key, user_token):
    url = 'https://ovp.peacocktv.com/video/playouts/live'

    headers = {
        'accept': 'application/vnd.playlive.v1+json',
        'content-type': 'application/vnd.playlive.v1+json',
        'x-skyott-activeterritory': country_code,
        'x-skyott-coppa': 'false',
        'x-skyott-device': device,
        'x-skyott-pinoverride': 'false',
        'x-skyott-platform': platform,
        'x-skyott-proposition': 'NBCUOTT',
        'x-skyott-provider': 'NBCU',
        'x-skyott-territory': country_code,
        'x-skyott-usertoken': user_token,
    }

    data = {
      "serviceKey": service_key,
      "device": {
        "capabilities": [
                #H265 EAC3
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H265",
                  "acodec": "EAC3",
                  "container": "TS"
                },
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H265",
                  "acodec": "EAC3",
                  "container": "ISOBMFF"
                },
                {
                  "container": "MP4",
                  "vcodec": "H265",
                  "acodec": "EAC3",
                  "protection": "WIDEVINE",
                  "transport": "DASH"
                },

                #H264 EAC3
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H264",
                  "acodec": "EAC3",
                  "container": "TS"
                },
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H264",
                  "acodec": "EAC3",
                  "container": "ISOBMFF"
                },
                {
                  "container": "MP4",
                  "vcodec": "H264",
                  "acodec": "EAC3",
                  "protection": "WIDEVINE",
                  "transport": "DASH"
                },

                #H265 AAC
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H265",
                  "acodec": "AAC",
                  "container": "TS"
                },
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H265",
                  "acodec": "AAC",
                  "container": "ISOBMFF"
                },
                {
                  "container": "MP4",
                  "vcodec": "H265",
                  "acodec": "AAC",
                  "protection": "WIDEVINE",
                  "transport": "DASH"
                },

                #H264 AAC
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H264",
                  "acodec": "AAC",
                  "container": "TS"
                },
                {
                  "transport": "DASH",
                  "protection": "WIDEVINE",
                  "vcodec": "H264",
                  "acodec": "AAC",
                  "container": "ISOBMFF"
                },
                {
                  "container": "MP4",
                  "vcodec": "H264",
                  "acodec": "AAC",
                  "protection": "WIDEVINE",
                  "transport": "DASH"
                },
            ],
            "model": "Nvidia Shield Android TV",
            "maxVideoFormat": 'UHD',
            "hdcpEnabled": 'false',
            "supportedColourSpaces": [
              "DV",
              "HDR10",
              "SDR"
            ],
        "timeShiftEnabled": 'false'
      },
      "parentalControlPin": 'null',
      "personaParentalControlRating": "9"
    }
    
    data = json.dumps(data)
    headers['x-sky-signature'] = calculate_signature('POST', url, headers, data)

    response = json.loads(requests.post(url, headers=headers, data=data).content)
    
    try:
        manifest_url = response['asset']['endpoints'][0]['url']
        license_url = response['protection']['licenceAcquisitionUrl']
    except:
        print('Live request failed')
        print(json.dumps(response))
        quit()
        
    do_cdm(manifest_url, license_url)
    
def round_dt(dt, delta):
    return datetime.min + round((dt - datetime.min) / delta) * delta

def channel_guide():
    headers = {
        'x-skyott-device': device,
        'x-skyott-platform': platform,
        'x-skyott-proposition': 'NBCUOTT',
        'x-skyott-territory': country_code,
    }

    params = {
        'startTime': round_dt(datetime.now(), timedelta(minutes=5)).astimezone().replace(microsecond=0, second=0).isoformat().replace(':00+', '+'),
        'contentSegments': 'D2C,Free',
    }

    response = json.loads(requests.get('https://web.clients.peacocktv.com/bff/channel_guide', params=params, headers=headers).content)
    
    try:
        channels = response['channels']
        
        r = []
        
        for c in channels:
            if 'VC' not in c['serviceKey']:
                r.append(c)
                
        return r
    except Exception as e:
        print('Error getting channels')
        print(e)
        quit()
    
def set_country_code():
    global country_code

    country_code_url = 'https://init.sky.com/'

    response = json.loads(requests.get(country_code_url).content)

    country_code = response['geoip']['country-code']
    
def get_token(skyCEsidmesso01, idsession):
    url = 'https://ovp.peacocktv.com/auth/tokens'
    
    cookies = {
        'skyCEsidmesso01': skyCEsidmesso01,
        'idsession': idsession,
    }
    
    headers = {
        'accept': 'application/vnd.tokens.v1+json',
        'content-type': 'application/vnd.tokens.v1+json',
        'x-skyott-activeterritory': country_code,
        'x-skyott-device': device,
        'x-skyott-platform': platform,
        'x-skyott-proposition': 'NBCUOTT',
        'x-skyott-provider': 'NBCU',
        'x-skyott-territory': country_code,
    }

    data = {
      "auth": {
        "authScheme": "MESSO",
        "authIssuer": "NOWTV",
        "provider": "NBCU",
        "providerTerritory": country_code,
        "proposition": "NBCUOTT",
      },
      "device": {
        "type": device,
        "platform": platform,
        "id": "rGy9qdFS9M7CcGHTksVy", #Value after all not completely irrelavant
        "drmDeviceId": "UNKNOWN"
      }
    }
    
    data = json.dumps(data)
    headers['x-sky-signature'] = calculate_signature('POST', url, headers, data)

    response = json.loads(requests.post(url, cookies=cookies, headers=headers, data=data).content)
    
    try:
        return response['userToken']
    except:
        print('Failed getting user token')
        print(response)
        if os.path.exists("skyCEsidmesso01.txt"):
            os.remove("skyCEsidmesso01.txt")
        
        print('\n')
        
        login = do_login()
        skyCEsidmesso01 = login[0]
        idsession = login[1]
        
        return get_token(skyCEsidmesso01, idsession)
        
def do_login():
    if (os.path.exists("skyCEsidmesso01.txt") == True):
        f = open("skyCEsidmesso01.txt", "r+")
        skyCEsidmesso01 = f.readline().strip('\n')
        idsession = f.readline().strip('\n')
        
        f.close()
        
        return [skyCEsidmesso01, idsession]
        
    else:
        headers = {
            'accept': 'application/vnd.siren+json',
            'content-type': 'application/x-www-form-urlencoded',
            'x-skyott-device': device,
            'x-skyott-platform': platform,
            'x-skyott-proposition': 'NBCUOTT',
            'x-skyott-provider': 'NBCU',
            'x-skyott-territory': country_code,
        }

        data = {
            'rememberMe': 'true',
            'isWeb': 'true',
            'userIdentifier': input('Username/Email: '),
            'password': pwinput.pwinput(),
        }

        response = requests.post(
            'https://rango.id.peacocktv.com/signin/service/international', headers=headers, data=data)
        
        skyCEsidmesso01 = response.cookies['skyCEsidmesso01']
        idsession = response.cookies['idsession']
        
        f = open("skyCEsidmesso01.txt", "w+")
        f.write(skyCEsidmesso01 + '\n' + idsession)
        f.close()
        
        return [skyCEsidmesso01, idsession]

def picker(array):
    choose = input()
    
    ascii_clear()
    
    if '-' in choose:
        choose = choose.split('-')
        n1 = int(choose[0])
        n2 = int(choose[1])
        
        if(n1 < 1 or n2 > len(array)):
            n1 = 1
        
        if(n2 > len(array)):
            n2 = len(array)
        
        
        r = []
        for i in range(n1, n2+1):
            r.append(array[i-1])
            
        return r
        
    try:
        choose = int(choose)
    except:
        return picker(array)
        
    if choose == 0:
        return picker(array)
    else:
        return [array[choose-1]]

def inspector(slug):
    r = {}
    
    headers = {
        'x-skyott-device': device,
        'x-skyott-platform': platform,
        'x-skyott-proposition': 'NBCUOTT',
        'x-skyott-territory': country_code,
    }

    if 'GMO' in slug:
        response = requests.get('https://atom.peacocktv.com/adapter-calypso/v3/query/node/content_id/' + slug.split('/')[2] + '?represent=(next%2Ct_recs%5Btake%3D1%5D(parents_shortforms))&features=upcoming', headers=headers)
    else:
        response = requests.get('https://atom.peacocktv.com/adapter-calypso/v3/query/node?slug=' + slug + '&represent=(items(items),recs[take=8],collections(items(items[take=8])),trailers)&features=upcoming', headers=headers)
    
    response = json.loads(response.content)
    
    attributes = response['attributes']
    
    r['title'] = attributes['title']
    
    print(attributes['title'] + ':')
    
    if 'providerVariantId' in attributes:
        r['providerVariantId'] = attributes['providerVariantId']
    else:
        relationships = response['relationships']
        data = relationships['items']['data']
        
        i = 1
        for d in data:
            print(' - Season ' + str(d['attributes']['seasonNumber']))
            i+=1
            
        choice = int(input('\nChoose season: '))
        
        episodes = data[choice-1]['relationships']['items']['data']
        
        ascii_clear()
        i = 1
        for e in episodes:
            print(str(i) + '. ' + e['attributes']['title'])
            i+=1
            
        choice = print('\nChoose episode (1-x for multiple): ', end='')
        
        r['episodes'] = picker(episodes)

    return r
    
def process_vod(slug):
    ascii_clear()
    inspection = inspector(slug)
    
    ascii_clear()
    print(inspection['title'] + ':')
    
    if 'providerVariantId' in inspection:
        vod_request(inspection['providerVariantId'], user_token)
    else:
        episodes = inspection['episodes']
        
        for e in episodes:
            attributes = e['attributes']
            print(' - ' + attributes['sortTitle'][-7:].replace(' ', '') + ' ' + attributes['title'])
            
            vod_request(attributes['providerVariantId'], user_token)
    
def search():
    query = input('\nEnter your search query: ')

    headers = {
        'x-skyott-device': device,
        'x-skyott-platform': platform,
        'x-skyott-proposition': 'NBCUOTT',
        'x-skyott-territory': country_code,
    }

    params = {
        'term': query,
        'limit': '10',
        'entityType': 'programme,series',
        'contentFormat': 'longform',
    }

    response = json.loads(requests.get('https://web.clients.peacocktv.com/bff/search/v2', params=params, headers=headers).content)
    
    try:
        results = response['data']['search']['results']
        
        i = 1
        for r in results:
            print(str(i) + '. ' + r['title'])
            i+=1
            
        choice = int(input('\nChoose result (0 to search again): '))
        
        if choice == 0:
            return search()
        else:
            return results[choice-1]['slug']
            
    except:
        print('Error getting search results')
        quit()
        
    

set_country_code()

ascii_clear() 

login = do_login()
skyCEsidmesso01 = login[0]
idsession = login[1]
 
user_token = get_token(skyCEsidmesso01, idsession)

ascii_clear()
print("Mode selection:")
print("1. Direct media url")
print("2. Search")
print("3. Live")
choose = int(input("\nChoice: "))

ascii_clear()

if choose == 1:
    video_url = input('Input media url: ').split('?')[0].split('/')
    slug = '/' + video_url[-3] + '/' + video_url[-2] + '/' + video_url[-1]
    
    process_vod(slug)
    
elif choose == 2:
    slug = search()
    
    process_vod(slug)
    
elif choose == 3:
    channels = channel_guide()
    
    i = 1
    for c in channels:
        print(str(i) + '. ' + c['channelTitle'])
        i+=1
    
    print('\nChoose channel (1-x for multiple): ', end='')
    
    choice = picker(channels)
    
    for c in choice:
        print(c['channelTitle'] + ':')
        live_request(c['serviceKey'], user_token)
else:
    print("Invalid mode selected")
import pyshark, os, json, csv, requests, whois, sys, ipinfo, re
from netaddr import IPNetwork, IPAddress
import util.util as util

# python3 parse_pcap_files.py different_network_experiments no_frida jan2024 y

# FIX: RuntimeError: This event loop is already running
import nest_asyncio
nest_asyncio.apply()

#TODO: update the IP ranges
aws_ranges = json.load(open('ip_ranges_cloud_providers_old/aws.json', 'r'))
oracle_ranges = json.load(open('ip_ranges_cloud_providers_old/oracle.json', 'r'))
digital_ocean_ranges = csv.reader(open('ip_ranges_cloud_providers_old/digitalocean.csv'), delimiter=',')
yandex_ranges = csv.reader(open('ip_ranges_cloud_providers_old/yandex.csv'), delimiter=',')
ibm_ranges = json.load(open('ip_ranges_cloud_providers_old/ibm.json', 'r'))
salesforce_ranges = json.load(open('ip_ranges_cloud_providers_old/salesforce.json', 'r'))
oracle_ranges = json.load(open('ip_ranges_cloud_providers_old/oracle.json', 'r'))
google_ranges = json.load(open('ip_ranges_cloud_providers_old/google.json', 'r'))
google_cloud_ranges = json.load(open('ip_ranges_cloud_providers_old/google-cloud.json', 'r'))
azure_ranges = json.load(open('ip_ranges_cloud_providers_old/azure.json', 'r'))
alibaba_ranges = json.load(open('ip_ranges_cloud_providers_old/alibaba.json', 'r'))
cloudflare_ranges = json.load(open('ip_ranges_cloud_providers_old/cloudflare.json', 'r'))

def check_oracle(e):
    for region in oracle_ranges['regions']:
        for cidr in region['cidrs']:
            ip_range = cidr['cidr']
            if IPAddress(e) in IPNetwork(ip_range):
                return True

def check_digital_ocean(e):
    for row in digital_ocean_ranges:
        if IPAddress(e) in IPNetwork(row[0]):
            return True

def check_yandex(e):
    for row in yandex_ranges:
        if IPAddress(e) in IPNetwork(row[1]):
            return True

def check_ip_range_generic(e, ranges):
    for range in ranges:
        if IPAddress(e) in IPNetwork(range):
            return True
    return False    

def check_ip_aws(ip):
    for range in aws_ranges['prefixes']:
        if IPAddress(ip) in IPNetwork(range['ip_prefix']):
            return True
    return False

def check_ip_google(ranges, ip):
    for range in ranges['prefixes']:
        try:
            if IPAddress(ip) in IPNetwork(range['ipv4Prefix']):
                return True
        except:
            pass
    return False

def check_ip_azure(ip):
    for item in azure_ranges['values']:
        for range in item['properties']['addressPrefixes']:
            if IPAddress(ip) in IPNetwork(range):
                return True
    return False

def check_new_providers(e):

    if check_ip_aws(e):
        return 'aws'
    if check_ip_google(google_ranges, e) or check_ip_google(google_cloud_ranges, e):
        return 'google'
    if check_oracle(e):
        return 'oracle'
    if check_digital_ocean(e):
        return 'digitalocean'
    if check_yandex(e):
        return 'yandex'
    if check_ip_range_generic(e, ibm_ranges):
        return 'ibm'
    if check_ip_range_generic(e, salesforce_ranges):
        return 'salesforce'
    if check_ip_azure(e):
        return 'azure'
    if check_ip_range_generic(e, cloudflare_ranges):
        return 'cloudflare'
    if check_ip_range_generic(e, alibaba_ranges):
        return 'alibaba'

    return ''

from util.domainCategorizationUtil import isAdCategoryNew, isCdnCategoryNew, isSocialNetworkCategoryNew

def getExodusCategories():
    result = {}
    exodusList = json.loads(requests.get("https://reports.exodus-privacy.eu.org/api/trackers").text)
    for _,item in exodusList['trackers'].items():
        currentSet = set()
        for x in item['network_signature'].split('|'):
            if len(x) == 0:
                continue
            x = x.replace('.*', '')
            x = x.replace('\\', '')
            if x.startswith('.'):
                x = x[1:]

            currentSet.add(x)
        if len(currentSet) == 0:
            continue
        if len(item['categories']) == 0:
            tmp = result.get('otherExodus', set())
            for x in currentSet:
                tmp.add(x)
            result['otherExodus'] = tmp
        
        for c in item['categories']:
            tmp = result.get(c, set())
            for x in currentSet:
                tmp.add(x)
            result[c] = tmp
    
    return result

exodusCategories = getExodusCategories()

def getClassification(subDomain):
    if subDomain.endswith("."):
        return subDomain
    for key,item in exodusCategories.items():
        toReturn = key
        if key == 'otherExodus' or key == 'Advertisement':
            toReturn = "adverts_and_trackers"
        if key == "Crash reporting":
            toReturn = 'crash_report'
        if key == 'Analytics':
            toReturn = 'analytics'
            
        subdomainSplitted = subDomain.split(".")
        for entry in item:
            entrySplitted = entry.split(".")
            if len(subdomainSplitted) >= len(entrySplitted):
                matched = True
                for i in range(0, len(entrySplitted)):
                    if entrySplitted[len(entrySplitted) - i - 1] != subdomainSplitted[len(subdomainSplitted) -i -1]:
                        matched = False
                        break
                if matched:
                    return toReturn
            
    if isCdnCategoryNew(subDomain):
        return "cdn"
    elif isAdCategoryNew(subDomain):
        return "adverts_and_trackers"
    elif isSocialNetworkCategoryNew(subDomain):
        return "social_net"
    
    return None

rfc1918 = re.compile('^(10(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|((172\.(1[6-9]|2[0-9]|3[01]))|192\.168)(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){2})$')

access_token = "<IP-info-token>"
handler = ipinfo.getHandler(access_token)

def get_ipinfo_country(e):
    if re.match(rfc1918, e) == None:
        try:
            details = handler.getDetails(e)
            return details.country
        except:
            return None

def check_against_all_dns_maps(e):
    for dns_map_filename in os.listdir(DNS_FOLDER_PCAPDROID):
        dns_map = json.load(open(DNS_FOLDER_PCAPDROID + dns_map_filename, 'r'))
        if e in dns_map:
            print(e, "corresponds to", dns_map[e])
            return dns_map[e]

    for dns_map_filename in os.listdir(DNS_FOLDER_MONIOTR):
        dns_map = json.load(open(DNS_FOLDER_MONIOTR + dns_map_filename, 'r'))
        if e in dns_map:
            print(e, "corresponds to", dns_map[e])
            return dns_map[e]

    for dns_map_filename in os.listdir(DNS_FOLDER_GENERIC):
        dns_map = json.load(open(DNS_FOLDER_GENERIC + dns_map_filename, 'r'))
        if e in dns_map and type(dns_map[e]) == str:
            print(e, "corresponds to", dns_map[e])
            return dns_map[e]

    return None

TOTAL_ANALYSIS = {}

EXPERIMENT_NAME = sys.argv[1]
FRIDA = sys.argv[2]
MONTH = sys.argv[3]

MONIOTR = sys.argv[4]

BASE_FOLDER = '/path/to/experiment/' + EXPERIMENT_NAME + '/' + FRIDA + '/' + MONTH + '/'

local_dns_map = {}

DNS_FOLDER_MONIOTR = BASE_FOLDER + 'dns_maps_moniotr/'
DNS_FOLDER_PCAPDROID = BASE_FOLDER + 'dns_maps_pcapdroid/'
DNS_FOLDER_GENERIC = './dns_maps/'

def get_filename_pcapdroid(file):
    if 'nofrida' in file:
        return '_'.join(file.replace('_nofrida.pcap', '').split('_')[:-1])
    else:
        return '_'.join(file.replace('.pcap', '').split('_')[:-1])

def iterate_over_moniotr_folders(f):
    for device in os.listdir(f):
        print('Analyzing', device)
        for experiment in os.listdir(f + '/' + device):
            print('Analyzing experiment', experiment)
            for filename in os.listdir(f + '/' + device + '/' + experiment):
                if '.pcap' in filename:
                    try:
                        app_name = device
                        if app_name not in TOTAL_ANALYSIS:
                            TOTAL_ANALYSIS[app_name] = {}

                        print('Analyzing: ', filename)
                        cap = pyshark.FileCapture(f + '/' + device + '/' + experiment + '/' + filename)

                        print('PCAP opened')

                        get_iteration = filename.replace('.pcap','')
                        print(get_iteration)

                        for packet in cap:

                            try:
                                source_IP = packet.ip.src
                                source_port = packet[packet.transport_layer].srcport
                                protocol = packet.highest_layer

                                if source_IP in local_dns_map:
                                    endpoint = local_dns_map[source_IP]
                                else:
                                    dns_match = check_against_all_dns_maps(source_IP)
                                    if dns_match != None:
                                        endpoint = dns_match
                                        local_dns_map[source_IP] = dns_match
                                    else:
                                        endpoint = source_IP
                                        local_dns_map[source_IP] = source_IP
                                    
                                if endpoint not in TOTAL_ANALYSIS[app_name]:
                                    print('NEW ENDPOINT!')
                                    TOTAL_ANALYSIS[app_name][endpoint] = {}
                                    TOTAL_ANALYSIS[app_name][endpoint]['IPs'] = [source_IP]
                                    TOTAL_ANALYSIS[app_name][endpoint]['ports'] = [source_port]
                                    TOTAL_ANALYSIS[app_name][endpoint]['protocols'] = [protocol]
                                    TOTAL_ANALYSIS[app_name][endpoint]['number_of_occurrences'] = {}
                                    TOTAL_ANALYSIS[app_name][endpoint]['number_of_occurrences']['file_' + get_iteration] = 1
                                    TOTAL_ANALYSIS[app_name][endpoint]['packet_sizes'] = {}
                                    TOTAL_ANALYSIS[app_name][endpoint]['packet_sizes']['file_' + get_iteration] = [packet.length]
                                    try:
                                        provider = check_new_providers(source_IP)
                                        TOTAL_ANALYSIS[app_name][endpoint]['provider'] = provider
                                    except:
                                        pass

                                    TOTAL_ANALYSIS[app_name][endpoint]['categorization'] = getClassification(endpoint)
                                    TOTAL_ANALYSIS[app_name][endpoint]['country'] = get_ipinfo_country(source_IP)
                                else:
                                    if source_IP not in TOTAL_ANALYSIS[app_name][endpoint]['IPs']:
                                        TOTAL_ANALYSIS[app_name][endpoint]['IPs'].append(source_IP)
                                    if source_port not in TOTAL_ANALYSIS[app_name][endpoint]['ports']:
                                        TOTAL_ANALYSIS[app_name][endpoint]['ports'].append(source_port)
                                    if protocol not in TOTAL_ANALYSIS[app_name][endpoint]['protocols']:
                                        TOTAL_ANALYSIS[app_name][endpoint]['protocols'].append(protocol)
                                    
                                    if ('file_' + get_iteration) not in TOTAL_ANALYSIS[app_name][endpoint]['number_of_occurrences']:
                                        TOTAL_ANALYSIS[app_name][endpoint]['number_of_occurrences']['file_' + get_iteration] = 1
                                    else:
                                        TOTAL_ANALYSIS[app_name][endpoint]['number_of_occurrences']['file_' + get_iteration] += 1
                                    
                                    if ('file_' + get_iteration) not in TOTAL_ANALYSIS[app_name][endpoint]['packet_sizes']:
                                        TOTAL_ANALYSIS[app_name][endpoint]['packet_sizes']['file_' + get_iteration] = [packet.length]
                                    else:
                                        TOTAL_ANALYSIS[app_name][endpoint]['packet_sizes']['file_' + get_iteration].append(packet.length)
                            except:
                                pass
                    except:
                        print("Error when analyzing:", filename)

    json.dump(TOTAL_ANALYSIS, open(BASE_FOLDER + 'moniotr' + '_' + FRIDA + '_' + MONTH + '.json', 'w+'))

def iterate_over_pcapdroid_folders(f):
    for filename in os.listdir(f):
        if '.pcap' in filename:
            try:
                device_name = get_filename_pcapdroid(filename)
                if device_name not in TOTAL_ANALYSIS:
                    TOTAL_ANALYSIS[device_name] = {}

                print('Analyzing: ', filename)
                cap = pyshark.FileCapture(f + filename)

                print('PCAP opened')

                get_iteration = filename.replace('.pcap','').replace('_nofrida', '').split('_')[-1]
                print("Running over Iteration number", get_iteration)

                for packet in cap:

                    source_IP = packet.ip.src
                    source_port = packet[packet.transport_layer].srcport
                    protocol = packet.highest_layer

                    if source_IP in local_dns_map:
                        endpoint = local_dns_map[source_IP]
                    else:
                        dns_match = check_against_all_dns_maps(source_IP)
                        if dns_match != None:
                            endpoint = dns_match
                            local_dns_map[source_IP] = dns_match
                        else:
                            endpoint = source_IP
                            local_dns_map[source_IP] = source_IP
                        

                    if endpoint not in TOTAL_ANALYSIS[device_name]:
                        print('NEW ENDPOINT!')
                        TOTAL_ANALYSIS[device_name][endpoint] = {}
                        TOTAL_ANALYSIS[device_name][endpoint]['IPs'] = [source_IP]
                        TOTAL_ANALYSIS[device_name][endpoint]['ports'] = [source_port]
                        TOTAL_ANALYSIS[device_name][endpoint]['protocols'] = [protocol]
                        TOTAL_ANALYSIS[device_name][endpoint]['number_of_occurrences'] = {}
                        TOTAL_ANALYSIS[device_name][endpoint]['number_of_occurrences']['file_' + get_iteration] = 1
                        TOTAL_ANALYSIS[device_name][endpoint]['packet_sizes'] = {}
                        TOTAL_ANALYSIS[device_name][endpoint]['packet_sizes']['file_' + get_iteration] = [packet.length]

                        try:
                            provider = check_new_providers(source_IP)
                            TOTAL_ANALYSIS[device_name][endpoint]['provider'] = provider
                        except:
                            TOTAL_ANALYSIS[device_name][endpoint]['provider'] = None

                        TOTAL_ANALYSIS[device_name][endpoint]['categorization'] = getClassification(endpoint)
                        TOTAL_ANALYSIS[device_name][endpoint]['country'] = get_ipinfo_country(source_IP)
                    else:
                        if source_IP not in TOTAL_ANALYSIS[device_name][endpoint]['IPs']:
                            TOTAL_ANALYSIS[device_name][endpoint]['IPs'].append(source_IP)
                        if source_port not in TOTAL_ANALYSIS[device_name][endpoint]['ports']:
                            TOTAL_ANALYSIS[device_name][endpoint]['ports'].append(source_port)
                        if protocol not in TOTAL_ANALYSIS[device_name][endpoint]['protocols']:
                            TOTAL_ANALYSIS[device_name][endpoint]['protocols'].append(protocol)
                        
                        if ('file_' + get_iteration) not in TOTAL_ANALYSIS[device_name][endpoint]['number_of_occurrences']:
                            TOTAL_ANALYSIS[device_name][endpoint]['number_of_occurrences']['file_' + get_iteration] = 1
                        else:
                            TOTAL_ANALYSIS[device_name][endpoint]['number_of_occurrences']['file_' + get_iteration] += 1
                        
                        if ('file_' + get_iteration) not in TOTAL_ANALYSIS[device_name][endpoint]['packet_sizes']:
                            TOTAL_ANALYSIS[device_name][endpoint]['packet_sizes']['file_' + get_iteration] = [packet.length]
                        else:
                            TOTAL_ANALYSIS[device_name][endpoint]['packet_sizes']['file_' + get_iteration].append(packet.length)
            except:
                print("Error when analyzing:", filename)

    json.dump(TOTAL_ANALYSIS, open(BASE_FOLDER + 'pcapdroid' + '_' + FRIDA + '_' + MONTH + '.json', 'w+'))

if MONIOTR == 'y':
    iterate_over_moniotr_folders(BASE_FOLDER + 'moniotr/')
else:
    print('PCAPDROID')
    iterate_over_pcapdroid_folders(BASE_FOLDER + 'PCAPdroid/')

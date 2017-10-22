from elasticsearch import Elasticsearch as ES
from elasticsearch_dsl import Search, Q
from app.config import config as cfg
from pprint import pprint
import itertools,ipaddress, requests, sys
from app import userlog
import datetime, json

def aggregator(service, indices, aggr_type, lt, gt, extra, mask):
    """
    Aggregates events out of the chosen indices and service depending on aggr_type.
    If enabled, produces the /n subnets in order to group the attackers.
    Lastly, lt and gt compose the time frame we are interested in.
    """
    internal_es = ES()
    
    doc_type = cfg['services_to_doctypes'][service]
    search = Search(using=internal_es, index=indices, doc_type=doc_type) \
        .query('match', service=service) \
        .extra(size=0)

    userlog.info('Running event aggregation on:-doc_type:\t {0}'.format(doc_type))
    userlog.info('\t\t\t\t -service:\t {0}'.format(service))
    userlog.info('\t\t\t\t -indices:\t {0}'.format(indices))
    userlog.info('Searching in the following timeframe: [{0},{1}]'.format(gt,lt))
    userlog.info('In a per {0} manner'.format(aggr_type))

    search = search.filter('range', ** { '@timestamp': {'gte': gt, 'lt': lt}})

    # Get current timestamp in utc
    now = datetime.datetime.utcnow()
    ltime = now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z"
    
    # Build document's base body
    source = {
        'district'          : cfg['general']['district'],
        'timeframe'         : '[{0},{1}]'.format(gt,lt),
        'aggregation_type'  : aggr_type,
        'source_indices'    : indices,
        '@timestamp'        : ltime,
        'source_doc_type'   : doc_type,
        'source_service'    : service,
    }
    # Enrich it with --extra flags
    if 'xcheck' in extra:
        source['blacklist_url'] = cfg['ssh']['blacklist_url']
    for token in extra: 
        source[token] = True
    
    blacklist = None
    if 'xcheck' in extra:
        blacklist = construct_blacklist()
    
    if aggr_type == 'victim':
        search.aggs.bucket('per_victim','terms', field='target_host.keyword', size=1000) \
                    .bucket('per_attacker', 'terms', field='source_ip.keyword', size=100000) 
        response = search.execute()
        
        source['victims'] = get_victims(response, blacklist, extra, mask)
    elif aggr_type == 'attacker':
        search.aggs.bucket('per_attacker', 'terms', field='source_ip.keyword', size=10000) 
        response = search.execute() 
        if 'cidrs' in extra:
            source['attackers'], source['cidrs'] = get_attackers(response, blacklist, extra, mask)
        else:
            source['attackers'] = get_attackers(response, blacklist, extra, mask)
    # Index to TTP only if debug is off and we aggregate per attacker
    if not cfg['general']['DEBUG'] and aggr_type == 'attacker':
        general_cfg = cfg['general']
        index = send_to_ttp(
            general_cfg['district'], 
            general_cfg['today'],
            general_cfg['ttp_ip'],
            general_cfg['ttp_port'],
            source,
            doc_type  # Aggrevents are stored in the same type as the source events
        )
        
        # In order to compare our latest results to another district's
        # we store our aggregations to 
        source['index'] = index 
        with open('latest_aggr.json','w+') as f:
            json.dump(source, f)
    elif aggr_type == 'victim':
        pprint_events(source, aggr_type)
        userlog.error('Victim-based aggregations cannot be pushed to TTP')
    else:
        pprint_events(source, aggr_type)
        userlog.info('Debug is turned on, no events will be pushed to TTP')

def send_to_ttp(district, today, ttp_ip, ttp_port, source, doc_type):
    """
    Sends the districts newly produced aggregation to the TTP.
    Returns the index used to store the documents
    """    
    index = '{0}-aggrevents-{1}'.format(district, today)
    userlog.info('Sending the aggregated events to TTP\'s ES instance')
    userlog.info('TTP ip:port : {0}:{1}'.format(ttp_ip, ttp_port))
    userlog.info('Index: {0} \t doc_type: {1} \t '.format(index, doc_type))    
    
    ttp_es = ES(hosts=ttp_ip, port=ttp_port)
    ttp_es.index(index=index, doc_type=doc_type, body=source)
    
    return index    

def get_attackers(response, blacklist, extra, mask):
    """
    Returns the attackers and cidrs ( if cidrs are enabled ).
    Attackers' pattern is shown below:
    [
        {attacker_ip: 187.22.11.3, attempts: 1234},
        ....
    ]

    If cidrs aggregation is enabled a 'cidrs' field is added
    and its format goes as follows:
    [
        {
            attackers:[
                {attacker_ip: 187.22.11.3, attempts: 1234},
                ....
            ]
        },
        network: 187.22.11.0/24,
        participants: 12
        percentage: 51.2
        total_attempts: 25500
    ]
    """
    attackers = []
    for attacker in response.aggregations.per_attacker.buckets:
        attacker_dict = {
            'attacker_ip'   : attacker.key,
            'attempts'      : attacker.doc_count,
        }
        if blacklist:
            blacklisted = (True if attacker.key in blacklist else False)
            attacker_dict['blacklisted'] =  blacklisted            
        attackers.append(attacker_dict)
    if 'cidrs' in extra:
        cidrs = ips_to_cidrs(attackers, mask)
        return (attackers, cidrs)
    return attackers

def get_victims(response, blacklist, extra, mask):
    """
    Return the a list of victims. 
    Every victim follow the format shown below:
    {
        victim_host: onosvm,
        total_attempts: 1234,
        attackers: [
            {attacker_ip: 79.126.7.7, attempts: 1234},
            ...
        ]
    } 
    
    If cidrs aggregation is enabled the 'attackers' dictionary format goes as follows:
    {
        attackers: {
            [
                {attacker_ip: 79.126.7.7, attempts: 1234},
                {attacker_ip: 79.126.7.8, attempts: 1234},
            ]
                network: 79.126.7.0/24,
                participants: 2,
                percentage: 0.22,
                total_attempts: 2478
            }
        }
    }
    """
    victims = []
    for victim in response.aggregations.per_victim.buckets:
        victim_dict = {
            'victim_host'   : victim.key,
            'total_attempts': victim.doc_count,
            'attackers'     : [],
        }
        for attacker in victim.per_attacker.buckets:
            attacker_dict = {
                'attacker_ip'   : attacker.key,
                'attempts'      : attacker.doc_count,
            }
            if blacklist:
                blacklisted = (True if attacker.key in blacklist else False)
                attacker_dict['blacklisted'] = blacklisted
            victim_dict['attackers'].append(attacker_dict)
        if 'cidrs' in extra:
            cidrs = ips_to_cidrs(victim_dict['attackers'], mask)
            victim_dict['cidrs'] = cidrs
        victims.append(victim_dict)
    return victims

def construct_blacklist():
    """
    Returns a set containing blacklisted IPs. 
    """
    url = cfg['ssh']['blacklist_url']
    try:
        req = requests.get(url, timeout=6)
    except requests.exceptions.Timeout:
        userlog.error('The requested blacklist at {0} timed out'.format(url))
        sys.exit()

    # Expands all /n networks into their respective IP ranges
    # There should be some ipaddress module magic that can handle that. 
    IP_blacklist = set()
    for line in req.text.split("\n"):
        if not line.startswith('#'):
            if '/' in line:
                for ip in ipaddress.ip_network(line):
                    IP_blacklist.add(ip.exploded)
            else:
                IP_blacklist.add(line) 
    return IP_blacklist

def ips_to_cidrs(attackers, mask):
    """
    Produces a list of dictionaries containing the cidrs alongside
    the corresponding attackers for each cidr
    
    Note: Read the "Implementation Concerns" wiki about the 
    conversion to list of dictionaries
    """
    cidrs={}
    total_attempts = 0
    for attacker in attackers:
        cidr = {}
        ip = ipaddress.ip_address(attacker['attacker_ip'])
        if type(ip) == ipaddress.IPv4Address:
            network = ipaddress.IPv4Network(ip.exploded+'/'+str(mask), strict=False).exploded
            if network in cidrs:
                cidrs[network]['participants'] += 1
                cidrs[network]['attackers'].append({
                    'attacker_ip'   : attacker['attacker_ip'], 
                    'attempts'      : attacker['attempts'],
                    })
            else:
                cidrs[network] = {
                'participants': 1, 
                'total_attempts': 0, 
                'attackers':[{
                    'attacker_ip'   : attacker['attacker_ip'], 
                    'attempts'      : attacker['attempts']
                    }]
                }
            cidrs[network]['total_attempts'] += attacker['attempts']
            total_attempts += attacker['attempts']
    output_cidrs = []
    for cidr,values in cidrs.items():
        cidrs[cidr]['percentage'] = \
            float(format((cidrs[cidr]['total_attempts'] / total_attempts) * 100, '.2f'))
        values['network'] = cidr
        output_cidrs.append(values)
    return output_cidrs

def pprint_events(events, type):
    """ Prints events in a human readable manner """
    if type == 'victim':
        if 'cidrs' in events:
            print('Victim: {0:20} | {1:20}'.format('CIDR', 'Attempts'))
            for victim in events['victims']:
                for cidr in victim['cidrs']:
                    print('\t {0:20} | {1:20} | {2}'.format(cidr['network'], cidr['total_attempts'], cidr['participants']))
            return
        for victim in events['victims']:
            print('Victim: {0}'.format(victim['victim_host']))
            print('\t {0:20} | {1:10}'.format('Attacker', 'Attempts'))
            for attacker in victim['attackers']:
                print('\t {0:20} | {1:10} | {2:20}'.format(attacker['attacker_ip'], attacker['attempts'], attacker['blacklisted']))
    else:
        if 'cidrs' in events:
            print('{0:20} | {1:20} | {2:20}'.format('CIDR', 'Attempts', 'Number of Participants'))
            cidrs = sorted(events['cidrs'], key=lambda k: k['participants'], reverse=True)
            for cidr in cidrs:
                cidr.pop('attackers')
                if cidr['total_attempts'] > 100:
                    print('{0:20} | {1:20} | {2:20}'.format(
                            cidr['network'], cidr['total_attempts'], cidr['participants']))
            cidrs = [d for d in cidrs if d['total_attempts'] > 100]
            import pandas as pd
            df = pd.DataFrame(cidrs)
            writer = pd.ExcelWriter('cidrs_netmode.xlsx', engine='xlsxwriter')
            df.to_excel(writer, sheet_name='1')
            writer.save()
            return
        print('{0:20} | {1:10} | {2}'.format('Attacker', 'Attempts', 'blacklisted'))
        for attacker in events['attackers']:
            print('{0:20} | {1:10} | {2}'.format(attacker['attacker_ip'], attacker['attempts'], attacker['blacklisted']))
        import pandas as pd
        df = pd.DataFrame(events['attackers'])
        writer = pd.ExcelWriter('singleIP_blacklisted_netmode.xlsx', engine='xlsxwriter')
        df.to_excel(writer, sheet_name='1')
        writer.save()

from elasticsearch import Elasticsearch as ES
from elasticsearch_dsl import Search, Q
from app.config import config as cfg
from pprint import pprint
import itertools,ipaddress, requests, sys
from app import userlog
import datetime, json

def aggregator(service, indices, aggr_type, lt, gt, extra, mask):
    internal_es = ES()
    
    if service=='sshd': doc_type='auth'
    elif service=='nginx': doc_type='webserver'
    else: doc_type='mail'
    
    s = Search(using=internal_es, index=indices, doc_type=doc_type) \
        .query('match', service=service) \
        .extra(size=0)

    userlog.info(' Running event aggregation on:-doc_type:\t {0}'.format(doc_type))
    userlog.info('\t\t\t\t -service:\t {0}'.format(service))
    userlog.info('\t\t\t\t -indices:\t {0}'.format(indices))
    userlog.info(' Searching in the following timeframe: [{0},{1}]'.format(gt,lt))
    userlog.info(' In a per {0} manner'.format(aggr_type))

    s = s.filter('range', ** { '@timestamp': {'gte': gt, 'lt': lt}})

    # Get current timestamp in utc
    now = datetime.datetime.utcnow()
    ltime = now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z"
    
    source = {
        'district'          : cfg['general']['district'],
        'timeframe'         : '[{0},{1}]'.format(gt,lt),
        'aggregation_type'  : aggr_type,
        'source_indices'    : indices,
        '@timestamp'        : ltime,
        'source_doc_type'   : doc_type,
        'source_service'    : service,
        }
    
    if 'xcheck' in extra:
        source['blacklist_url'] = cfg['ssh']['blacklist_url']
    for token in extra:
        source[token] = True
    
    blacklist = None
    if 'xcheck' in extra and service=='sshd':
        blacklist = construct_blacklist()
    
    if aggr_type == 'victim':
        s.aggs.bucket('per_victim','terms', field='target_host.keyword', size=1000) \
            .bucket('per_attacker', 'terms', field='source_ip.keyword', size=100000) 
        response = s.execute()
        
        victims = []
        for victim in response.aggregations.per_victim.buckets:
            victim_dict = {
                'victim_host'   : victim.key,
                'total_attempts': victim.doc_count,
                'attackers'     : [],
            }
            for attacker in victim.per_attacker.buckets:
                #print('\t\t{0:15} | {1:7} | {2}'.format(attacker.key, attacker.doc_count, blacklisted))
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
        source['victims'] = victims    
    elif aggr_type == 'attacker':
        s.aggs.bucket('per_attacker', 'terms', field='source_ip.keyword', size=10000) 
        response = s.execute() 
        
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
            source['cidrs'] = cidrs
        source['attackers'] = attackers
    #pprint(source)
    if not cfg['general']['DEBUG'] and aggr_type == 'attacker':
        index = '{0}-aggrevents-{1}'.format(cfg['general']['district'], cfg['general']['today'])
        ttp_ip = cfg['general']['ttp_ip']
        ttp_port = cfg['general']['ttp_port']
        userlog.info(' Sending the aggregated events to TTP\'s ES instance')
        userlog.info(' TTP ip:port : {0}:{1}'.format(ttp_ip, ttp_port))
        userlog.info(' Index: {0} \t doc_type: {1} \t '.format(index, doc_type))    
        ttp_es = ES(hosts=ttp_ip, port=ttp_port)
        ttp_es.index(index=index, doc_type=doc_type, body=source)
        source['index'] = index
        with open('latest_aggr.json','w+') as f:
            json.dump(source, f)
    else:
        pprint(source)
        userlog.info(' Debug is turned on, no events will be pushed to TTP')

def construct_blacklist():
    url = cfg['ssh']['blacklist_url']
    try:
        req = requests.get(url, timeout=6)
    except requests.exceptions.Timeout:
        userlog.error(' The requested blacklist at {0} timed out'.format(url))
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
        cidrs[cidr]['percentage'] = float(format((cidrs[cidr]['total_attempts'] / total_attempts) * 100, '.2f'))
        values['network'] = cidr
        output_cidrs.append(values)
    return output_cidrs

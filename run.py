from elasticsearch import Elasticsearch
from pprint import pprint
from argparse import RawTextHelpFormatter
from sys import exit
import argparse

from app.detectors import *
from app.post_processors import aggregator
from app.config import service_list, extra
from app.config import config as cfg
from app import userlog

client = Elasticsearch()


def build_parser():
    parser = argparse.ArgumentParser(prog="ESclient", formatter_class=RawTextHelpFormatter,
                epilog='Example of uses:\n'
                '1 - Print out an index\'s produced events for ssh on debug mode:\n'
                '\t python run.py -s ssh -i netmode-logstash-2017.06.06\n'
                '2 - Index multiple indices\' produced events for nginx:\n'
                '\t python run.py -s nginx -i netmode-logstash-2017.06.0* --debug_off\n'
                '3 - Print out the events\' aggregations for the past 24 hours:\n'
                '\t python run.py -s ssh -i netmode-events-2017.06.06 --agg victim -lt now -gt now-1d\n'
                'For more information, refer to the arguments\' help')
    parser.add_argument('-i', '--indices', nargs='*',
                        help='Insert the index/ces you want to produce events for.\n'
                                'You can use wildcards and/or list of indices', default='*')
    parser.add_argument('-r' ,'--debug_off', required=False, action='store_true',
                        help='Run with DEBUG mode off. \n'
                              'WARNING: This will not output any events to stdout but '
                              'index them in today\'s index')
    parser.add_argument('-s', '--service', choices=service_list,
                        help='Insert the service that you want to audit', required=True)
    parser.add_argument('--agg' ,'-a',
                        help='Indicate if you want to use the aggregator.',
                        choices=['victim', 'attacker'])
    parser.add_argument('-lt', metavar='LOWER THAN',
                        help='Along with the -gt setting, define the timeframe of the aggregation.\n'
                        'Tip: Be sure to use the right indices for the selected timeframe')
    parser.add_argument('-gt', metavar='GREATER THAN',
                        help='Along with the -lt setting, define the timeframe of the aggregation.\n'
                        'Tip: Be sure to use the right indices for the selected timeframe')
    parser.add_argument('--extra', choices=extra, nargs='*', default=[],
                        help='Choose which post-aggregation actions are needed.\n'
                        'For more info, refer to --help')
    parser.add_argument('--mask', type=int, choices=range(16,33),
                        help='If you chose to aggregate into cidrs, define the mask.\n')
    return parser

def validate_arguments(args):
    if args.debug_off: 
        cfg['general']['DEBUG']=False
        userlog.warn('Debug mode is off, events will be reindexed')
    if args.agg:
        if not args.lt or not args.gt:
            userlog.error('option --agg/-a requires -lt and -gt arguments to be set')
            exit()
        if any('logstash' in index for index in args.indices):
            userlog.error('Invalid index {0}'.format(args.indices))
            userlog.error('Cannot perform aggregations on raw log files ')
            exit()
        if 'xcheck' in args.extra and not args.service=='sshd':
            userlog.error('The blacklist crosscheck concerns only sshd adversaries')
            exit()
        if 'cidrs' in args.extra and not args.mask:
            userlog.error('Aggregating into cidrs requires you to define the --mask option ')
            exit()
    else:
        # If we are doing event-production, the user must choose "log-lines" indices
        if any('events' in index for index in args.indices):
            userlog.error('Invalid index {0}'.format(args.indices))
            userlog.error('Cannot perform processing on events')
            exit()


def main():
    parser = build_parser()
    
    # If no arguments are passed, print out help
    try:
        args = parser.parse_args()
    except:
        parser.print_help()
        exit()
    validate_arguments(args)
    
    if args.agg:
        aggregator(args.service, args.indices, args.agg, args.lt, args.gt, args.extra, args.mask)
    else:
        if args.service == 'nginx':
           detector = WebDetector(client, doc_type='webserver', service='nginx', indices=args.indices)
        elif args.service == 'dovecot': 
           detector = DovecotDetector(client, doc_type='mail', service='dovecot', indices=args.indices)
        elif args.service == 'sshd': 
           detector = SSHDetector(client, doc_type='auth', service='sshd', indices=args.indices)
        
        response = detector.query_es()
        detector.process_response(response)

if __name__ == "__main__":
    main()
from datetime import datetime
from pprint import pprint

from app.utils import register_proc, whoami
from app.detectors import *
from app.config import config as cfg
from app.config import ssh_list


@register_proc(SSHDetector)
def ssh_processor(batch):
	processor = whoami()
	for hit in batch:
		# ssh accepts a whitespace as username,
		# but it is not caught by logstash's regex
		username = ' ' if not hasattr(hit, 'username') else hit.username
		event= {
			'event_processor':	processor,
			'@timestamp' : 		hit['@timestamp'],
			'source_ip': 		hit.attacker_ip,
			'target_host': 		hit.host,
			'contributor': 		hit.district,
			'service': 			hit.service,
			'attack_type': 		'brute_force',

		}
		if hit.logline_type=='SSHBANNERGRAB':
			event.update({
					'attack_type': 'fingerprinting',
					'description': 'Version fingerprinting',
				})
		elif hit.logline_type=='SSHFAILEDLOGIN' or hit.logline_type=='SSHFAILEDLOGINF':
			
			event.update({
				'description': 'Failed attempt on a valid user',
				'specifics': {
					'username': username,
					'valid_user': True,
					'method': 'PW',
				},
			})
		elif hit.logline_type=='SSHINVALIDUSER' or hit.logline_type=='SSHINVALIDUSERF':
			event.update({
				'description': 'Failed attempt to login on an invalid user',
				'specifics': {
					'username': username,
					'valid_user': False,
					'method': 'PW',
				},
			})
		elif hit.host not in ssh_list:
			if hit.logline_type=='SSHINVALIDUSERPKI':
				event.update({
					'description': 'Failed attempt to login on an invalid user',
					'specifics': {
						'username': username,
						'valid_user': False,
						'method': 'PKI',
					},
				})
			elif hit.logline_type=='SSHCONNCLOSED' or hit.logline_type=='SSHCONNCLOSEDPKI':
				event.update({	
					'specifics': {
						'method': 'PKI',
					},
					'description': 'Failed all auth methods on a password-disabled ssh daemon',
				})
		else:
			#print('Non-type ', hit.message, hit.logline_type)
			continue
		yield event

@register_proc(DovecotDetector)
def mail_processor(batch):
	who = whoami()
	for hit in batch:
		if hasattr(hit, 'user'):
			domain = '-' if not hasattr(hit, 'domain') else hit.domain
			yield {
				'@timestamp' : 		hit['@timestamp'],
				'event_processor':	who, 
				'source_ip': 		hit.attacker_ip,
				'target_host': 		hit.host,
				'contributor': 		hit.district,
				'service': 			hit.service,
				'attack_type': 		'brute_force',
				'specifics': {
					'domain': 	domain,
					'user': 	hit.user,
				}
			}

@register_proc(WebDetector)
def non_wp_website(batch):
	processor = whoami()
	wp_list = ['wp-login', 'wp-content', 'wordpress', 'xmlrpc.php']
	for hit in batch:
		if any(token in hit.message for token in wp_list):
			yield {
				'@timestamp' : 		hit['@timestamp'],
				'event_processor':	processor, 
				'source_ip': 		hit.attacker_ip,
				'target_host': 		hit.host,
				'contributor': 		hit.district,
				'service': 			hit.service,
				'attack_type': 		'wpscan',
				'specifics': {
					'request':		hit.request,
					'response': 	hit.response,
					'bytes': 		hit.bytes,
					'http_method': 	hit.verb,
				},
			}

@register_proc(WebDetector)
def non_php_website(batch):
	processor = whoami()
	wp_list = ['wp-login', 'wp-content', 'wordpress', 'xmlrpc.php']
	for hit in batch:
		if 'MALFORMED_REQUEST' not in hit.tags:
			if 'php' in hit.request:
				if not any(token in hit.message for token in wp_list):
					yield {
						'event_processor':	processor, 
						'@timestamp' : 		hit['@timestamp'],
						'source_ip': 		hit.attacker_ip,
						'target_host': 		hit.host,
						'contributor': 		hit.district,
						'service': 			hit.service,
						'attack_type': 		'fingerprinting',
						'specifics': {
							'request':		hit.request,
							'response': 	hit.response,
							'bytes': 		hit.bytes,
							'http_method': 	hit.verb,
						},
					}

@register_proc(WebDetector)
def malformed_requests(batch):
	processor = whoami()
	for hit in batch:
		if 'MALFORMED_REQUEST' in hit.tags:
			yield {
				'@timestamp' : hit['@timestamp'],
				'event_processor':	processor, 
				'source_ip': 	hit.attacker_ip,
				'target_host': 	hit.host,
				'contributor': 	hit.district,
				'service': 		hit.service,
				'attack_type': 	'Known Exploit Iteration',
				'specifics': {
					'malformed_request': hit.malformed_req,
				},
			}
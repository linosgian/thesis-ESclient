import datetime
import os
DISTRICT = os.environ['DISTRICT']

EVENT_INDEX_MIDDLE_NAME = 'events'
today = datetime.date.today().strftime("%Y.%m.%d")
service_list = ['sshd', 'nginx', 'dovecot', 'all']
ssh_list = ['snf-749092', 'snf-754841']
extra = ['xcheck', 'cidrs', 'country']

config = {
    'general':{
        'today'             : today,
        'ttp_ip'            : '147.102.13.154',
        'ttp_port'          : '58080',
        'DEBUG'             : True,
        'district'          : DISTRICT,
        'batch_size'        : 1500,
        'todays_index'      : '{0}-{1}-{2}'.format(DISTRICT, EVENT_INDEX_MIDDLE_NAME, today),
    },
    'ssh':{
        'blacklist_url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset'
    }
}

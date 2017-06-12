from abc import ABC,abstractmethod
from elasticsearch import helpers
from elasticsearch_dsl import Search, Q
from pprint import pprint
import itertools

from .config import config as cfg
from . import userlog

class BaseDetector(ABC):

    def __init__(self, es_client, service, indices="*", doc_type=None):
        self.indices = indices
        self.doc_type = doc_type
        self.es_client = es_client
        self.service = service
        userlog.info(' Running event generation on: -doc_type:\t {0}'.format(doc_type))
        userlog.info('\t\t\t\t -service:\t {0}'.format(service))
        userlog.info('\t\t\t\t -indices:\t {0}'.format(indices))

    @abstractmethod
    def query_es(self, *args):
        pass

    def process_response(self):
        userlog.info(' Received a generator for the requested queries')
        batch_size = cfg['general']['batch_size']
        index = cfg['general']['todays_index']
        es = self.es_client

        if hasattr(self, 'processors'):
            if not es.indices.exists(index=index):
                userlog.info(' Index {0} does not exist'.format(index))
                es.indices.create(index)
                userlog.info(' Created index')
            else: userlog.info(' Index {0} exists'.format(index))
            gen = iter(())
            userlog.info(' Batch processing started...')
            while True:
                batch = list(itertools.islice(self.response,batch_size))
                for proc in self.processors:
                    batch_gen = ({
                            '_type': self.doc_type,
                            '_index': index,
                            '_source': event_source,
                        } for event_source in proc(batch))
                    gen = itertools.chain(batch_gen,gen)
                if len(batch) != batch_size:
                    break
            userlog.info(' Batch processing ended...')
            for x in gen:
                if cfg['general']['DEBUG']:
                    pprint(x)
                    print('\n' + '-----------------------------','\n')
                else:
                    userlog.info(' Indexing started...')
                    doc_count = helpers.bulk(es, gen)
                    userlog.info(' {0} documents were inserted into {1}...'.format(doc_count, index))

class SSHDetector(BaseDetector):

    def query_es(self):
        batch_size = cfg['general']['batch_size']
            #.filter('range', ** { '@timestamp': {'gte': 'now-1h', 'lt': 'now'}}) \
        s = Search(using=self.es_client, index=self.indices, doc_type=self.doc_type) \
            .query('match', service=self.service) \
            .sort('@timestamp') \
            .params(preserve_order=True, size=batch_size)
        self.response = s.scan()


class DovecotDetector(BaseDetector):

    def query_es(self):
        # @timestamp contains the time the log line arrived at logstash
        # Not the event's timestamp
        s = Search(using=self.es_client, index=self.indices, doc_type=self.doc_type) \
            .query(~Q('match', user='<VALID_USER>')) \
            .query('match', service=self.service) \
            .sort('@timestamp') \
            .params(preserve_order=True)        
        self.response = s.scan()

class WebDetector(BaseDetector):

    def query_es(self):
        s = Search(using=self.es_client, index=self.indices, doc_type=self.doc_type) \
            .query('match', service=self.service) \
            .sort('@timestamp') \
            .params(preserve_order=True)
        self.response = s.scan()

import app.processors

from abc import ABC,abstractmethod
from elasticsearch import helpers
from elasticsearch_dsl import Search, Q
from pprint import pprint
import itertools

from .config import config as cfg
from . import userlog

class BaseDetector(ABC):
    """
    Base detector class. Contains the unified process_response logic
    """
    
    def __init__(self, es_client, service, indices="*", doc_type=None):
        self.indices = indices
        self.doc_type = doc_type
        self.es_client = es_client
        self.service = service
        userlog.info('Running event generation on: -doc_type:\t {0}'.format(doc_type))
        userlog.info('\t\t\t\t -service:\t {0}'.format(service))
        userlog.info('\t\t\t\t -indices:\t {0}'.format(indices))

    @abstractmethod
    def build_query(self, *args):
        pass

    def execute_query(self, gt):
        """ This function is used in order to perform periodic processing of events """
        query = self.build_query()
        if gt:
            search = query.filter('range', ** { '@timestamp': {'gte': 'now-'+gt, 'lt': 'now'}})
            return search.scan() 
        return query.scan()    
    def process_response(self, response):
        """
        Parses loglines, produces events, and reindexes them back to today's index
        Log lines' index pattern is: "netmode-logstash-YYYY.MM.DD",
        Whereas, events follow this: "netmode-events-YYYY.MM.DD". 
        """
        userlog.info('Received a generator for the requested queries')
        batch_size = cfg['general']['batch_size']
        index = cfg['general']['todays_index']
        es = self.es_client

        # If there are any registered processors for the calling object's class
        if hasattr(self, 'processors'):
            if not es.indices.exists(index=index):
                userlog.info('Index {0} does not exist'.format(index))
                es.indices.create(index)
                userlog.info('Created index')
            else: 
                userlog.info('Index {0} exists'.format(index))
            
            userlog.info('Batch processing started...')
            gen = iter(())
            while True:
                # Evaluate the response's generator in batches
                batch = list(itertools.islice(response, batch_size))
                for proc in self.processors:
                    batch_gen = ({
                            '_type': self.doc_type,
                            '_index': index,
                            '_source': event_source,
                        } for event_source in proc(batch))
                    gen = itertools.chain(batch_gen, gen)
                 
                if len(batch) != batch_size:  # we reached the last batch
                    break
            userlog.info('Batch processing ended...')
            if cfg['general']['DEBUG']:
                for x in gen:
                    pprint(x['_source']['@timestamp'])
                    #print('\n' + '-----------------------------','\n')
            else:
                userlog.info('Indexing started...')
                doc_count = helpers.bulk(es, gen)
                userlog.info('{0} documents were inserted into {1}...'.format(doc_count, index))

class SSHDetector(BaseDetector):

    def build_query(self):
        batch_size = cfg['general']['batch_size']
        s = Search(using=self.es_client, index=self.indices, doc_type=self.doc_type) \
            .query('match', service=self.service) \
            .sort('@timestamp') \
            .params(preserve_order=True, size=batch_size)
        return s 


class DovecotDetector(BaseDetector):

    def build_query(self):
        s = Search(using=self.es_client, index=self.indices, doc_type=self.doc_type) \
            .query(~Q('match', user='<VALID_USER>')) \
            .query('match', service=self.service) \
            .sort('@timestamp') \
            .params(preserve_order=True)        
        return s

class WebDetector(BaseDetector):

    def build_query(self):
        s = Search(using=self.es_client, index=self.indices, doc_type=self.doc_type) \
            .query('match', service=self.service) \
            .sort('@timestamp') \
            .params(preserve_order=True)
        return s

import app.processors

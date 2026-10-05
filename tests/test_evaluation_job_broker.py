"""Real private-socket controls for normalized independent job observations."""
import socket
import unittest
import uuid
from evaluation.job_broker import JobBroker, JobObservationError, read_job
from evaluation.fault_broker import send, receive


class JobBrokerTest(unittest.TestCase):
    def setUp(self):
        self.identity=str(uuid.uuid4());self.calls=[]
        self.observation=dict(export_id=self.identity,status='running',processing_attempts=1,
            active_lease=True,lease_fingerprint='a'*64,published_artifacts=0,completion_events=0)
    def reader(self, identity):
        self.calls.append(identity)
        return dict(self.observation,connection_password='parent-only',sql='parent-only')
    def request(self, broker, value):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(2);connection.connect(str(broker.path))
            with connection.makefile('rwb') as stream:send(stream,value);return receive(stream)
    def test_projection_permissions_identity_and_cleanup(self):
        with JobBroker(self.reader) as broker:
            self.assertEqual(read_job(broker.configuration,self.identity),self.observation)
            self.assertEqual(self.calls,[self.identity])
            self.assertEqual(broker.path.stat().st_mode & 0o777,0o600)
            self.assertEqual(broker.directory.stat().st_mode & 0o777,0o700)
        self.assertFalse(broker.directory.exists())
    def test_invalid_identity_token_and_sql_cannot_reach_reader(self):
        with JobBroker(self.reader) as broker:
            for value in (dict(token='wrong',export_id=self.identity),
                          dict(token=broker.token,export_id=self.identity,sql='DELETE'),
                          dict(token=broker.token,export_id='not-a-uuid')):
                self.assertIn(self.request(broker,value)['status'],('refused','inconclusive'))
        self.assertEqual(self.calls,[])
    def test_missing_and_wrong_identity_or_truthy_lease_are_inconclusive(self):
        for changes in ({'export_id':str(uuid.uuid4())},{'active_lease':1},
                        {'lease_fingerprint':'private-raw-owner'}, {'processing_attempts':True}):
            with self.subTest(changes=changes):
                self.observation.update(changes)
                with JobBroker(self.reader) as broker:
                    with self.assertRaises(JobObservationError):read_job(broker.configuration,self.identity)
                self.setUp()
        del self.observation['published_artifacts']
        with JobBroker(self.reader) as broker:
            with self.assertRaises(JobObservationError):read_job(broker.configuration,self.identity)
    def test_requirement_violating_counts_are_not_hidden_by_projection(self):
        self.observation.update(processing_attempts=4,published_artifacts=2,completion_events=2)
        with JobBroker(self.reader) as broker:
            self.assertEqual(read_job(broker.configuration,self.identity),self.observation)
    def test_budget_and_endpoint_revocation_do_not_read_again(self):
        with JobBroker(self.reader,max_requests=1) as broker:
            configuration=broker.configuration
            read_job(configuration,self.identity)
            with self.assertRaises(JobObservationError):read_job(configuration,self.identity)
        with self.assertRaises(JobObservationError):read_job(configuration,self.identity)
        self.assertEqual(self.calls,[self.identity])
    def test_exception_details_are_redacted(self):
        def reader(identity):raise RuntimeError('secret-password-and-schema')
        with JobBroker(reader) as broker:
            response=self.request(broker,dict(token=broker.token,export_id=self.identity))
            self.assertEqual(response,{'status':'inconclusive'})

    def test_durable_read_uses_distinct_reader_and_never_returns_artifact_count(self):
        from evaluation.job_broker import read_lease
        calls=[]
        def durable(identity):calls.append(identity);return dict(self.observation,published_artifacts=999,password='private')
        with JobBroker(self.reader,durable_reader=durable) as broker:
            value=read_lease(broker.configuration,self.identity)
            self.assertNotIn('published_artifacts',value);self.assertNotIn('password',value)
            self.assertEqual(value['active_lease'],True);self.assertEqual(calls,[self.identity])
            self.assertEqual(self.calls,[])
            self.assertEqual(read_job(broker.configuration,self.identity)['published_artifacts'],0)

    def test_missing_durable_callback_cannot_fall_back_to_combined_reader(self):
        from evaluation.job_broker import read_lease
        with JobBroker(self.reader) as broker:
            with self.assertRaises(JobObservationError):read_lease(broker.configuration,self.identity)
        self.assertEqual(self.calls,[])

    def test_unreviewed_read_modes_and_extra_arguments_never_execute_either_reader(self):
        from evaluation.job_broker import read_lease
        calls=[]
        with JobBroker(self.reader,durable_reader=lambda identity:calls.append(identity)) as broker:
            for operation in ('sql','read_job',None):
                response=self.request(broker,dict(token=broker.token,export_id=self.identity,operation=operation))
                self.assertEqual(response,{'status':'refused'})
            response=self.request(broker,dict(token=broker.token,export_id=self.identity,operation='read_lease',table='app'))
            self.assertEqual(response,{'status':'refused'})
        self.assertEqual(calls,[]);self.assertEqual(self.calls,[])

    def test_combined_and_durable_reads_share_the_same_request_budget(self):
        from evaluation.job_broker import read_lease
        with JobBroker(self.reader,durable_reader=self.reader,max_requests=1) as broker:
            read_lease(broker.configuration,self.identity)
            with self.assertRaises(JobObservationError):read_job(broker.configuration,self.identity)
        self.assertEqual(self.calls,[self.identity])

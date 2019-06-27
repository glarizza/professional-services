# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.


__author__ = ('Jeff McCune <jeff@openinfrastructure.co>, '
              'Gary Larizza <gary@openinfrastructure.co>')

import base64
import json
import logging
import os
import google.cloud.logging
from enum import Enum
from google.cloud.logging.resource import Resource
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from typing import List


class RuntimeState:
    pass


RuntimeState.app = None


class Result(Enum):
    """Results of the cleanup.

    A NOT_PROCESSED results is likely a result of losing the race against the
    VM delete operation and is intended to signal to the user they may need to
    cleanup DNS records using another mechanism (e.g. manually).
    """
    OK = 0
    NOT_PROCESSED = 1


class Detail(Enum):
    """Detailed results of the cleanup

    A LOST_RACE result indicates user intervention is necessary.
    """
    NO_OP = 0
    NO_MATCHES = 1
    DELETED = 2
    VM_NO_IP = 3
    IGNORED_EVENT = 4
    LOST_RACE = 5


class EventHandler():
    """Handles a single event.

    Intended to follow the lifecycle of a single trigger event.
    """

    IP_NOT_AVAILABLE_MSG = (
        "Could not get IP address. Obtaining the IP is not guaranteed "
        "because of race condition with VM deletion.  "
        "Aborting with no action taken"
    )

    RESULT_DETAIL_MESSAGES = {
        Detail.NO_OP: "{} No action taken",
        Detail.NO_MATCHES: "{} matches no DNS records",
        Detail.DELETED: "{} matches DNS records",
        Detail.VM_NO_IP: "{} has no IP address",
        Detail.LOST_RACE: "{} does not exist likely (LOST_RACE)",
        Detail.IGNORED_EVENT: (
            "No action taken, event_type is not GCE_API_CALL for {}"
        ),
    }

    RESULT_SEVERITY = {
        Detail.NO_OP: 'INFO',
        Detail.VM_NO_IP: 'INFO',
        Detail.IGNORED_EVENT: 'INFO',
        Detail.LOST_RACE: 'WARNING',
    }

    def __init__(self, app, data, context=None):
        self.config = self.load_configuration()
        self.log = app.log
        self.cloud_log = app.cloud_log
        self.compute = app.compute
        self.dns = app.dns
        self.event_id = context.event_id if context else context
        self.validate_data(data)
        event = self.parse_data(data)
        self.type = event['type']
        self.project = event['project']
        self.zone = event['zone']
        self.vm_name = event['vm_name']
        self.vm_uri = "projects/{}/zones/{}/instances/{}".format(
            self.project, self.zone, self.vm_name
        )
        # https://cloud.google.com/functions/docs/env-var
        self.function_project = os.getenv('GCP_PROJECT')
        self.function_region = os.getenv('FUNCTION_REGION')
        self.function_name = os.getenv('FUNCTION_NAME')

    def load_configuration(self):
        """Loads configuration from the environment

        Returns:
          Dictionary of config key/values.
        """
        dns_project = os.getenv('DNS_VM_GC_DNS_PROJECT')
        if not dns_project:
            raise(EnvironmentError(
                'Env var DNS_VM_GC_DNS_PROJECT is required.'
            ))
        dns_zones = os.getenv('DNS_VM_GC_DNS_ZONES')
        if not dns_zones:
            raise(EnvironmentError('Env var DNS_VM_GC_DNS_ZONES is required'))
        zones = [v.strip() for v in dns_zones.split(',')]
        return {
            'dns_project': dns_project,
            'dns_zones': zones,
        }

    def log_result(self, result: Result, detail: Detail, num_deleted: int = 0):
        """Logs the final results for reporting via structured logs"""
        msg = self.RESULT_DETAIL_MESSAGES[detail].format(self.vm_uri)
        self.log.info(msg)
        self.log_struct(
            msg,
            {
                'result': result.name,
                'detail': detail.name,
                'num_deleted': num_deleted,
            },
            severity=self.RESULT_SEVERITY.get(detail, 'NOTICE')
        )

    def run(self):
        """Processes an event"""
        msg = "Handling event_id='{}' vm='{}'".format(
            self.event_id,
            self.vm_uri
        )
        self.log.info(msg)
        if not self.validate_event_type(self.type):
            self.log_result(Result.OK, Detail.IGNORED_EVENT)
            return 0

        instance = self.get_instance(self.project, self.zone, self.vm_name)
        if not instance:
            self.log_result(Result.NOT_PROCESSED, Detail.LOST_RACE)
            return 0

        ip = self.ip_address(instance)
        if not ip:
            self.log_result(Result.OK, Detail.VM_NO_IP)
            return 0

        num_deleted = 0
        dns_project = self.config['dns_project']
        for zone in self.config['dns_zones']:
            records = self.dns_records(dns_project, zone)
            candidates = self.find_garbage(self.vm_name, ip, records)
            for record in candidates:
                self.delete_record(dns_project, zone, record)
                num_deleted += 1
        if num_deleted > 0:
            detail = Detail.DELETED
        else:
            detail = Detail.NO_MATCHES
        self.log_result(Result.OK, detail, num_deleted)
        return num_deleted

    def log_struct(self, msg: str, struct: dict = {}, **kw):
        """Logs a structured message

        Annotated with metadata about the event being handled.

        Args:
          msg: Text message to log via message key in log structure.
          struct: Additional key/value attributes to log in the log structure.
          **kw: (optional) additional keyword arguments for the entry.  See
            :class:`~google.cloud.logging.entries.LogEntry`.
        """
        # Note: If the log name has a prefix of
        # `cloudfunctions.googleapis.com/cloud-functions` then message will not
        # be parsed from jsonPayload in the Console UI.
        log_name = (
            'projects/{}/logs/reports%2F{}'
        ).format(self.function_project, self.function_name)
        jsonPayload = {'vm_uri': self.vm_uri}
        jsonPayload.update(struct)
        resource_labels = {
            'function_name': self.function_name,
            'project_id': self.function_project,
            'region': self.function_region,
        }
        resource = Resource(labels=resource_labels, type='cloud_function')
        log_entry = {
            'log_name': log_name,
            'labels': {
                'event_id': self.event_id,
            },
            'severity': 'INFO',
            'resource': resource,
        }
        log_entry.update(kw)
        jsonPayload['message'] = msg
        self.cloud_log.log_struct(info=jsonPayload, **log_entry)

    def dns_records(self, project: str, managed_zone: str) -> List[dict]:
        """Obtain a collection of A records from Cloud DNS.

        See
        https://cloud.google.com/dns/docs/reference/v1/resourceRecordSets/list

        Args:
            project: The project containing the Cloud DNS managed zone.
              Typically the VPC Host project.
            managed_zone: The Cloud DNS managed zone to scan for records.
        """
        request = self.dns.resourceRecordSets().list(
            project=project,
            managedZone=managed_zone
        )
        records = []
        while request is not None:
            try:
                response = request.execute()
                for resource_record_set in response['rrsets']:
                    records.append(resource_record_set)
                request = self.dns.resourceRecordSets().list_next(
                    previous_request=request,
                    previous_response=response)
            except HttpError as err:
                msg = (
                    'Could not get DNS records.  Check managed '
                    'zones specified in DNS_VM_GC_DNS_ZONES '
                    'exist in DNS_VM_GC_DNS_PROJECT.  Detail: {}'
                ).format(err)
                self.log.error(msg)
                request = None
        return records

    def delete_record(self, project: str, managed_zone: str, record: dict):
        """Deletes a DNS Resource Record Set.

        See https://cloud.google.com/dns/docs/reference/v1/changes

        Args:
            project: The project containing the Cloud DNS managed zone.
              Typically the VPC Host project.
            managed_zone: The Cloud DNS managed zone to scan for records.
            record: A DNS record dictionary, must have at least 'name' key and
              value.
        """
        change = {"kind": "dns#change", "deletions": [record]}
        request = self.dns.changes().create(
            project=project,
            managedZone=managed_zone,
            body=change)
        response = request.execute()
        struct = {
            'action': "DELETED",
            'dns_project': project,
            'dns_managed_zone': managed_zone,
            'dns_record': record,
            'response': response
        }
        msg = "DNS Record {} deleted, matched {} ({})".format(
            record['name'],
            self.vm_uri,
            struct['action'],
        )
        self.log.info(msg)
        self.log_struct(msg, struct=struct, severity='NOTICE')
        return response

    def find_garbage(self,
                     instance: str,
                     ip: str,
                     records: List[dict]) -> List[str]:
        """Identifies DNS records to delete.

        Records are included in the results to be deleted if:
        1. The leftmost portion of the DNS Record name matches the vm name.
        2. AND the rrdatas value has exactly one value matching the ip.
        3. AND the DNS record type is 'A'

        Args:
            instance: The name of the instance.
            ip: The IP address of the VM being deleted.
            records: A list of DNS records as returned from the dns v1 API.
        """
        candidates = []

        for record in records:
            if 'A' != record['type']:
                continue
            if instance != record['name'].split('.')[0]:
                continue
            if [ip] != record['rrdatas']:
                continue
            candidates.append(record)
        return candidates

    def ip_address(self, instance):
        """Parses the primary network IP from a VM instance Resource.

        Args:
        Returns: (string) ip address or None if IP not found
        """
        ip = None
        if 'networkInterfaces' in instance:
            networkInterfaces = instance['networkInterfaces']
            if networkInterfaces:
                if 'networkIP' in networkInterfaces[0]:
                    ip = networkInterfaces[0]['networkIP']
        return ip

    def get_instance(self, project, compute_zone, instance):
        """Return the results of the compute.instances.get API call
        Args:
            project (string): The project
            compute_zone (string): The compute_zone
            instance (string): The instance name
        Returns:
            (dict) De-serialized JSON API response as a Dictionary.
        """
        try:
            result = self.compute.instances().get(
                project=project,
                zone=compute_zone,
                instance=instance).execute()
        except HttpError as err:
            self.log.error("Getting {}: {}".format(self.vm_uri, err))
            result = {}
        return result

    def validate_data(self, data):
        """Validates event data passed in"""
        if 'data' not in data:
            raise KeyError(
                "Error: Expected data dictionary contains key 'data'"
            )

    def parse_data(self, data):
        """Parses event data

        Args:
          data (dict): The value of the data key of the trigger event.

        Returns a dictionary with the following keys:
          project: The project the VM resided in.
          zone: The compute zone the VM resided in.
          instance: The name of the VM instance.
          type: The event type, e.g. GCE_API_CALL
        """
        # Event metadata comes from Stackdriver as a JSON string
        event_json = base64.b64decode(data['data']).decode('utf-8')
        event = json.loads(event_json)

        struct = {
            'project': event['resource']['labels']['project_id'],
            'zone': event['resource']['labels']['zone'],
            'vm_name': event['labels'][
                'compute.googleapis.com/resource_name'
            ],
            'type': event['jsonPayload']['event_type'],
        }

        return struct

    def validate_event_type(self, event_type):
        """Validates the event type is one which should be handled.

        At this time only GCE_API_CALL events are handled.

        Returns (bool): True if the event should be handled.
        """
        if event_type == 'GCE_API_CALL':
            return True
        return False


class DnsVmGcApp():
    """Holds state for the lifetime of a function

    Application controller holding state which persists across multiple trigger
    events.  Primarily configuration, network API clients, and logging API
    clients.
    """
    LOGNAME = 'dns-vm-gc'

    def __init__(self, http=None, session=None):
        """Initializes the app to handle multiple events

        Args:
            http: httplib2.Http, An instance of httplib2.Http or something that
                acts like it that HTTP requests will be made through.
            session: A requests.Session instance intended for mocking out the
                Stackdriver API when under test.
        """
        # Log clients
        self.log = self.setup_python_logging()
        self.cloud_log = self.setup_cloud_logging(session=session)
        # API clients
        self.compute = discovery.build('compute', 'v1', http=http)
        self.dns = discovery.build('dns', 'v1', http=http)

    def setup_python_logging(self):
        """Configures Python logging system

        Python logs are sent to STDOUT and STDERR by default.  In GCF, these
        logs are associated on execution_id.
        """
        if os.getenv('DEBUG'):
            level = logging.DEBUG
        else:
            level = logging.INFO
        # Make googleapiclient less noisy.
        # See https://github.com/googleapis/google-api-python-client/issues/299
        api_logger = logging.getLogger('googleapiclient')
        api_logger.setLevel(logging.ERROR)
        # Set level of our logger.
        log = logging.getLogger(self.LOGNAME)
        log.setLevel(level)
        return log

    def setup_cloud_logging(self, session=None):
        """Configures Structured Logging for results reporting

        Structured logs are used to report the results of execution.  This is
        different from Python logging used to report step by step progress of a
        single execution.

        Args:
            session: A requests.Session instance intended for mocking out the
                Stackdriver API when under test.
        """
        if session:
            client = google.cloud.logging.Client(
                _http=session,
                _use_grpc=False
            )
        else:
            client = google.cloud.logging.Client()
        logger = client.logger(self.LOGNAME)
        return logger

    def handle_event(self, data, context=None):
        """Background Cloud Function to delete DNS A records when VM is deleted.

        Args:
            data (dict): The dictionary with data specific to this type of
                event.
            context (google.cloud.functions.Context): The Cloud Functions event
                metadata.
        Returns:
            Number of records deleted across all managed zones.
        """
        handler = EventHandler(app=self, data=data, context=context)
        result = handler.run()
        return result


def main(data, context=None, http=None, session=None):
    if RuntimeState.app is None:
        RuntimeState.app = DnsVmGcApp(http=http, session=session)
    result = RuntimeState.app.handle_event(data, context)
    return result


def dns_vm_gc(data, context=None):
    main(data, context)

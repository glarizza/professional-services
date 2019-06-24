Structured Logging
===

Approaches taken to obtain structured logging in Google Cloud Functions.

Event ID is available in:
 * context.event_id for Background Functions

Structured logs in GKE:
 * https://groups.google.com/forum/#!topic/google-stackdriver-discussion/FiA03-3kvH8

jsonPayload
===

When logging via Stackdriver directly, we need to include the following
metadata to get the logs showing up associated with the function execution
correctly:

In particular:

 * trace
 * labels.execution_id
 * resource.type
 * resource.labels.project_id
 * resource.labels.region
 * resource.labels.function_name

```json
[
  {
    "textPayload": "{'handlers': [<StreamHandler (NOTSET)>, <StreamHandler (WARNING)>]}",
    "insertId": "000000-51ce43fc-8d3f-4a65-8994-df475bf82f83",
    "resource": {
      "type": "cloud_function",
      "labels": {
        "project_id": "dns-logging",
        "region": "us-central1",
        "function_name": "dns_vm_gc"
      }
    },
    "timestamp": "2019-06-24T17:22:43.753Z",
    "severity": "INFO",
    "labels": {
      "execution_id": "fca0oerxlh2r"
    },
    "logName": "projects/dns-logging/logs/cloudfunctions.googleapis.com%2Fcloud-functions",
    "trace": "projects/dns-logging/traces/3fd2a5d90a6ce51f5226b3f452a13efb",
    "receiveTimestamp": "2019-06-24T17:22:49.776685512Z"
  }
]
```

Data from environment variables
===

FUNCTION_REGION: us-central1
GCP_PROJECT: 

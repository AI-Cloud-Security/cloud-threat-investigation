"""AWS CloudTrail management and S3 data events.

Indicator rules (all deterministic, see docs/INTEGRATION_GUIDE.md):

* public_access: the caller is anonymous (``ANONYMOUS_PRINCIPAL``), the request
  grants access to the ``AllUsers``/``AuthenticatedUsers`` groups, sets a
  ``public-read``/``public-read-write`` canned ACL, attaches a policy that allows
  ``"Principal": "*"``, or the resource is listed in ``public_resources``.
* unusual_region: ``awsRegion`` is not in the configured ``expected_regions``.
* large_read: ``additionalEventData.bytesTransferredOut`` is at least
  ``large_read_bytes``.
"""
import json
from typing import Any

from .base import AdapterConfig, unusual_region

PUBLIC_GROUPS = ('acs.amazonaws.com/groups/global/AllUsers', 'acs.amazonaws.com/groups/global/AuthenticatedUsers')
PUBLIC_ACLS = {'public-read', 'public-read-write'}
ANONYMOUS = {'ANONYMOUS_PRINCIPAL', 'anonymous'}


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _principal(identity: dict[str, Any]) -> str:
    issuer = (identity.get('sessionContext') or {}).get('sessionIssuer') or {}
    arn = _text(identity.get('arn'))
    return (_text(issuer.get('userName')) or _text(identity.get('userName'))
            or (arn.rsplit('/', 1)[-1] if arn else None) or _text(identity.get('principalId'))
            or _text(identity.get('invokedBy')) or 'anonymous')


def _policy_allows_everyone(policy: Any) -> bool:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return False
    if not isinstance(policy, dict):
        return False
    statements = policy.get('Statement', [])
    statements = statements if isinstance(statements, list) else [statements]
    for statement in statements:
        if not isinstance(statement, dict) or statement.get('Effect') != 'Allow':
            continue
        principal = statement.get('Principal')
        if principal == '*' or (isinstance(principal, dict) and '*' in (
                principal.get('AWS') if isinstance(principal.get('AWS'), list) else [principal.get('AWS')])):
            return True
    return False


def _public(event: dict[str, Any]) -> bool:
    identity = event.get('userIdentity') or {}
    if identity.get('accountId') in ANONYMOUS or identity.get('type') == 'AnonymousPrincipal':
        return True
    request = event.get('requestParameters') or {}
    if not isinstance(request, dict):
        return False
    acl = request.get('x-amz-acl')
    acls = acl if isinstance(acl, list) else [acl]
    if any(isinstance(item, str) and item in PUBLIC_ACLS for item in acls):
        return True
    serialized = json.dumps(request.get('AccessControlPolicy', ''))
    if any(group in serialized for group in PUBLIC_GROUPS):
        return True
    return _policy_allows_everyone(request.get('bucketPolicy') or request.get('policy'))


def _resource(event: dict[str, Any]) -> str:
    request = event.get('requestParameters') or {}
    if isinstance(request, dict) and _text(request.get('bucketName')):
        return request['bucketName']
    for resource in event.get('resources') or []:
        if isinstance(resource, dict) and _text(resource.get('ARN')):
            return resource['ARN']
    return _text(event.get('eventSource')) or 'unknown-resource'


def to_record(event: dict[str, Any], config: AdapterConfig) -> dict[str, Any] | None:
    """Map one CloudTrail event, or return None when configured to skip it."""
    if event.get('errorCode') and not config.include_failed:
        return None
    identity = event.get('userIdentity') or {}
    tenant = config.tenant or _text(event.get('recipientAccountId')) or _text(identity.get('accountId'))
    if not tenant:
        raise ValueError('No tenant: set "tenant" in adapter settings or include recipientAccountId')
    transferred = (event.get('additionalEventData') or {}).get('bytesTransferredOut', 0)
    transferred = int(transferred) if isinstance(transferred, (int, float)) and not isinstance(transferred, bool) else 0
    return {
        'tenant': tenant,
        'event_id': event['eventID'],
        'timestamp': event['eventTime'],
        'principal': _principal(identity),
        'resource': _resource(event),
        'action': event['eventName'],
        'public_access': int(_public(event)),
        'unusual_region': unusual_region(_text(event.get('awsRegion')), config),
        'large_read': int(transferred >= config.large_read_bytes),
        'source_format': 'aws-cloudtrail',
        'source_event': event,
    }

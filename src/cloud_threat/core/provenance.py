"""Content-addressed evidence dependency graph."""
import base64
import hashlib
from typing import Any
from .canonical import digest, short_id
from .scoring import MODEL, FEATURES, score, counterfactual
from .validation import normalize, validate_policy

def build(raws: list[bytes], policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Construct a deterministic graph from one validated incident and policy."""
    validate_policy(policy)
    if not raws:
        raise ValueError('No events')
    if len(raws) > 10000:
        raise ValueError('An incident may contain at most 10000 records')
    events = {}
    for raw in raws:
        e = normalize(raw)
        key = (e['tenant'], e['event_id'])
        if key in events:
            if raw != events[key][0]:
                raise ValueError('Conflicting duplicate event')
        else:
            events[key] = (raw, e)
    ordered = [events[k] for k in sorted(events)]
    if len({e['tenant'] for raw, e in ordered}) != 1:
        raise ValueError('Cross-tenant input rejected')
    tenant = ordered[0][1]['tenant']
    if policy['tenant'] != tenant:
        raise ValueError('Policy tenant mismatch')
    principals = {e['principal'] for raw, e in ordered}
    resources = {e['resource'] for raw, e in ordered}
    if len(principals) != 1 or len(resources) != 1:
        raise ValueError('One principal and resource per sample incident')
    nodes = {}

    def node(kind, data, parents=()):
        obj = {'kind': kind, 'data': data, 'parents': sorted(parents)}
        h = digest(obj)
        nodes[h] = obj
        return h
    normalized = []
    for raw, e in ordered:
        r = node('raw', {'bytes_b64': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest()})
        normalized.append(node('normalized', e, [r]))
    f = {k: max((e[k] for raw, e in ordered)) for k in FEATURES}
    feat = node('features', {'values': f, 'transform': 'binary-max-v1'}, normalized)
    mod = node('model', MODEL)
    pol = node('policy', policy)
    s = score(f)
    decision = {'risk_points': s, 'threshold': MODEL['threshold'], 'alert': s >= MODEL['threshold'], 'probability': False}
    dec = node('decision', decision, [feat, mod])
    explanation = {'baseline': MODEL['baseline'], 'unit': 'risk_points', 'contributions': {k: MODEL['weights'][k] * f[k] for k in FEATURES}, 'summary': 'Illustrative score contributions. No causal claim or calibrated confidence.'}
    att = node('attribution', explanation, [dec, feat, mod])
    cf = counterfactual(f, policy, next(iter(principals)), next(iter(resources)))
    cfn = node('counterfactual', cf, [pol, dec, feat, mod])
    root = node('evidence', {'tenant': tenant, 'schema': 'evidence-v1', 'encoding': 'integer-json-v1'}, [att, cfn])
    return ({'root': root, 'nodes': nodes, 'short_id': short_id(root)}, decision, explanation, cf)

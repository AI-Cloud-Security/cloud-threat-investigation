"""Explicit reference scoring and a bounded, policy-constrained action search."""
import itertools
from typing import Any

MODEL = {
    'id': 'illustrative-additive-v1',
    'baseline': 10,
    'weights': {'public_access': 35, 'unusual_region': 20, 'large_read': 30},
    'threshold': 70,
    'score_unit': 'risk_points',
    'trained': False,
}
FEATURES = tuple(MODEL['weights'])
ACTIONS = (
    ('disable_public_access', 'public_access', 1),
    ('limit_read_volume', 'large_read', 2),
)


def score(features: dict[str, int]) -> int:
    """Return additive risk points; this output is not a probability."""
    return MODEL['baseline'] + sum(
        MODEL['weights'][feature] * features[feature] for feature in FEATURES
    )


def counterfactual(
    features: dict[str, int],
    policy: dict[str, Any],
    principal: str,
    resource: str,
) -> dict[str, Any]:
    """Select the minimum-cost permitted change within the declared action set."""
    if score(features) < MODEL['threshold']:
        return {
            'status': 'no_change_required', 'score': score(features),
            'cost': 0, 'actions': [], 'applied': False,
        }
    allowed = {(edge['principal'], edge['resource'], edge['action']) for edge in policy['edges']}
    best: dict[str, Any] | None = None
    for size in range(1, len(ACTIONS) + 1):
        for candidate in itertools.combinations(ACTIONS, size):
            if any(
                (principal, resource, action) not in allowed or features[feature] == 0
                for action, feature, _ in candidate
            ):
                continue
            preview = dict(features)
            for _, feature, _ in candidate:
                preview[feature] = 0
            cost = sum(weight for _, _, weight in candidate)
            preview_score = score(preview)
            if preview_score >= MODEL['threshold']:
                continue
            if best is not None and cost >= best['cost']:
                continue
            best = {
                'status': 'feasible',
                'actions': [action for action, _, _ in candidate],
                'features': preview,
                'score': preview_score,
                'cost': cost,
                'minimality': 'exact over 2 declared binary actions',
                'applied': False,
            }
    return best or {
        'status': 'no_feasible_candidate',
        'applied': False,
        'minimality': 'searched 2 declared binary actions',
    }

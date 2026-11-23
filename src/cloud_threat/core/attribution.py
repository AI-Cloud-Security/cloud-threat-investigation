"""Model-agnostic feature attribution in one canonical format.

Every supported model family produces the same structure::

    {
      "model": {"id": ..., "family": ...},
      "unit": "risk_points" | "log_odds" | "score",
      "baseline": <expected output with no feature evidence>,
      "output": <model output for these features>,
      "contributions": [{"feature", "value", "contribution", "lower", "upper"}, ...],
      "method": <how contributions were computed>,
      "complete": true  # baseline + sum(contributions) == output
    }

Supported families:

* ``linear`` (including the built-in additive profile): contribution = weight x value.
  Optional ``weight_stderr`` gives a 95% interval per contribution.
* ``logistic``: contributions in log-odds; ``probability`` is also reported.
* ``tree_ensemble``: path-based (Saabas) contributions for gradient-boosted or
  random-forest trees whose internal nodes carry their mean ``value``.

Contributions are exact decompositions of each model's output. They describe
how the model reached its number, not whether the activity was malicious.
"""
import argparse
import json
import math
from pathlib import Path
from typing import Any

Z95 = 1.959963984540054


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f'{name} must be a finite number')
    return value


def _features(model: dict[str, Any], features: dict[str, Any]) -> dict[str, float]:
    names = model.get('features') or sorted(model.get('weights', {}))
    missing = [name for name in names if name not in features]
    if missing:
        raise ValueError(f'Missing feature values: {", ".join(missing)}')
    return {name: _number(features[name], name) for name in names}


def _linear_terms(model: dict[str, Any], values: dict[str, float]) -> list[dict[str, Any]]:
    weights = model.get('weights')
    if not isinstance(weights, dict) or not weights:
        raise ValueError('Linear and logistic models require a weights object')
    stderr = model.get('weight_stderr', {})
    rows = []
    for name in sorted(weights):
        weight = _number(weights[name], f'weight {name}')
        value = values[name]
        contribution = weight * value
        spread = Z95 * abs(_number(stderr.get(name, 0), f'weight_stderr {name}') * value)
        rows.append({'feature': name, 'value': value, 'contribution': contribution,
                     'lower': contribution - spread, 'upper': contribution + spread})
    return rows


def _walk_tree(node: dict[str, Any], values: dict[str, float], totals: dict[str, float]) -> tuple[float, float]:
    """Return (root value, leaf value), adding per-feature path deltas to totals."""
    root_value = _number(node.get('value', node.get('leaf')), 'tree node value')
    current = node
    depth = 0
    while 'leaf' not in current:
        depth += 1
        if depth > 256:
            raise ValueError('Tree depth exceeds 256')
        feature = current.get('feature')
        if feature not in values:
            raise ValueError(f'Tree splits on unknown feature: {feature}')
        threshold = _number(current.get('threshold'), 'tree threshold')
        child = current.get('left') if values[feature] <= threshold else current.get('right')
        if not isinstance(child, dict):
            raise ValueError('Tree split requires left and right child nodes')
        parent_value = _number(current.get('value'), 'tree node value')
        child_value = _number(child.get('value', child.get('leaf')), 'tree node value')
        totals[feature] += child_value - parent_value
        current = child
    return root_value, _number(current['leaf'], 'tree leaf')


def explain(model: dict[str, Any], features: dict[str, Any]) -> dict[str, Any]:
    """Explain one prediction in the canonical contribution format."""
    if not isinstance(model, dict):
        raise ValueError('Model must be a JSON object')
    family = model.get('family')
    identity = {'id': str(model.get('id', 'unnamed-model')), 'family': family}
    if family in ('linear', 'additive', 'logistic'):
        values = _features(model, features)
        rows = _linear_terms(model, values)
        baseline = _number(model.get('intercept', model.get('baseline', 0)), 'intercept')
        output = baseline + sum(row['contribution'] for row in rows)
        result = {'model': identity, 'unit': model.get('unit', 'log_odds' if family == 'logistic' else 'score'),
                  'baseline': baseline, 'output': output, 'contributions': rows,
                  'method': 'coefficient x value' + (' (95% interval from weight_stderr)' if model.get('weight_stderr') else '')}
        if family == 'logistic':
            result['probability'] = 1 / (1 + math.exp(-output))
    elif family == 'tree_ensemble':
        trees = model.get('trees')
        if not isinstance(trees, list) or not trees:
            raise ValueError('Tree ensembles require a nonempty trees list')
        values = _features(model, features)
        totals = {name: 0.0 for name in values}
        baseline = _number(model.get('base_score', 0), 'base_score')
        output = baseline
        for tree in trees:
            root_value, leaf = _walk_tree(tree, values, totals)
            baseline += root_value
            output += leaf
        rows = [{'feature': name, 'value': values[name], 'contribution': totals[name],
                 'lower': totals[name], 'upper': totals[name]} for name in sorted(values)]
        result = {'model': identity, 'unit': model.get('unit', 'score'), 'baseline': baseline, 'output': output,
                  'contributions': rows, 'method': 'path-based (Saabas) decomposition; no interval available'}
    else:
        raise ValueError('Supported model families: linear, additive, logistic, tree_ensemble')
    total = result['baseline'] + sum(row['contribution'] for row in result['contributions'])
    result['complete'] = math.isclose(total, result['output'], rel_tol=1e-9, abs_tol=1e-9)
    result['contributions'].sort(key=lambda row: -abs(row['contribution']))
    return result


def builtin_profile() -> dict[str, Any]:
    """Express the workspace's additive scoring profile as a linear model."""
    from .scoring import MODEL
    return {'id': MODEL['id'], 'family': 'additive', 'intercept': MODEL['baseline'],
            'weights': dict(MODEL['weights']), 'unit': MODEL['score_unit']}


def main() -> None:
    parser = argparse.ArgumentParser(prog='explain', description='Explain one model prediction in the canonical contribution format.')
    parser.add_argument('--model', type=Path, help='Model JSON (default: the built-in additive profile)')
    parser.add_argument('--features', type=Path, required=True, help='JSON object of feature values')
    args = parser.parse_args()
    try:
        model = json.loads(args.model.read_text(encoding='utf8')) if args.model else builtin_profile()
        features = json.loads(args.features.read_text(encoding='utf8'))
        print(json.dumps(explain(model, features), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f'Explanation failed: {error}\n')


if __name__ == '__main__':
    main()

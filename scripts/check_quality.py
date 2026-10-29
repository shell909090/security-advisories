"""Enforce per-function complexity and per-file maintainability limits."""
import argparse
import ast
from pathlib import Path

from cognitive_complexity.api import get_cognitive_complexity
from mccabe import PathGraphingAstVisitor
from radon.metrics import mi_visit

ROOT = Path(__file__).resolve().parents[1]


def source_files():
    for path in sorted(ROOT.rglob('*.py')):
        relative = path.relative_to(ROOT)
        if any(part.startswith('.') or part == '__pycache__' for part in relative.parts):
            continue
        yield path


def complexity_results(tree):
    visitor = PathGraphingAstVisitor()
    visitor.preorder(tree, visitor)
    for name, graph in sorted(visitor.graphs.items()):
        yield 'McCabe', name, graph.lineno, graph.complexity(), 10
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield 'Cognitive', node.name, node.lineno, get_cognitive_complexity(node), 15


def check_file(path, mode):
    source = path.read_text(encoding='utf-8')
    label = path.relative_to(ROOT)
    failures = 0
    if mode in ('all', 'complexity'):
        for metric, name, line, value, limit in complexity_results(ast.parse(source)):
            if value > limit:
                print(f'FAIL {label}:{line} {name}: {metric} {value} > {limit}')
                failures += 1
    if mode in ('all', 'mi'):
        value = mi_visit(source, multi=True)
        status = 'PASS' if value >= 30 else 'FAIL'
        print(f'{status} {label}: MI {value:.2f} (minimum 30)')
        failures += value < 30
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('all', 'complexity', 'mi'), default='all', nargs='?')
    args = parser.parse_args()
    paths = list(source_files())
    failures = sum(check_file(path, args.mode) for path in paths)
    print(f'{len(paths)} Python files checked; {failures} violations')
    return int(bool(failures))


if __name__ == '__main__':
    raise SystemExit(main())

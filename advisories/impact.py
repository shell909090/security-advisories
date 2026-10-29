"""Conservative evidence labels, not AI analysis or exploitability verdicts."""
import re

RULES = {
    'UAF': r'\buse[- ]after[- ]free\b',
    'Crash': r'\bcrash(?:es|ing)?\b',
    'DoS': r'\bdenial[- ]of[- ]service\b',
    'Sandbox Escape': r'\bsandbox (?:escape|bypass)\b|\b(?:code|execution) outside (?:the )?sandbox\b',
    'Privilege Escalation': r'\bprivilege escalation\b|\bescalat\w* privileges\b',
    'File Read': r'\b(?:arbitrary|unauthenticated|local) file read\b',
    'File Write': r'\barbitrary file write\b|\bfile writes? outside\b',
    'Code Execution': r'\b(?:arbitrary|remote) (?:code|command) execution\b|\bexecute arbitrary (?:code|commands)\b',
}
NEGATED = re.compile(r"\b(?:not|no|never|cannot|can't|without|unlikely|hypothetical)\b", re.I)


def sentence_tags(sentence):
    if NEGATED.search(sentence):
        return set()
    tags = {tag for tag, pattern in RULES.items() if re.search(pattern, sentence, re.I)}
    remote = re.search(r'\bremote (?:attacker|code execution|command execution)\b', sentence, re.I)
    if 'Code Execution' in tags and remote:
        tags.remove('Code Execution')
        tags.add('RCE')
    return tags


def impact_tags(row):
    tags = set()
    for evidence in row['evidence']:
        text = (evidence.get('title') or '') + '\n' + (evidence.get('description') or '')
        for sentence in re.split(r'(?<=[.!?])\s+|\n', text):
            tags.update(sentence_tags(sentence))
    return sorted(tags)

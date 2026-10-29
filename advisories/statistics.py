"""Human-readable, per-source update diagnostics."""


def render_statistics(sources):
    lines = ['Source statistics (response_bytes = decoded body bytes):']
    for source, values in sources.items():
        lines.append(source + ': ' + ', '.join(f'{key}={value}' for key, value in values.items()))
    return '\n'.join(lines)

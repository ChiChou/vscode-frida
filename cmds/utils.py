from pathlib import Path

def read_agent():
    with (Path(__file__).parent.parent / 'agent' / '_agent.js').open('r', encoding='utf8') as fp:
        return fp.read()

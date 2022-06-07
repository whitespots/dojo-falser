from pprint import pprint

import requests
import os

defectdojo_url = os.environ.get('SEC_DD_URL', '')
defectdojo_key = os.environ.get('SEC_DD_KEY', '')

description_patterns = [
    'integrity'
]

patterns = {
    'entropy': [
        'svg',
        'go.sum',
        'package.json',
        'package-lock.json',
        'integrity'
    ]
}


def get_findings():
    offset = 0
    count = 10
    result = {
        'results': []
    }
    while len(result.get('results')) < count:
        response = requests.get(
            url=f'{defectdojo_url}/api/v2/findings/?verified=False&active=True&duplicate=False&limit=100&offset={offset}',
            headers={
                'Authorization': f'Token {defectdojo_key}'
            }
        ).json()
        count = response.get('count')
        result['results'].extend(response.get('results'))
        offset += 100
    return result


def mark_as_false(id):
    return requests.request(
        method='PATCH',
        url=f'{defectdojo_url}/api/v2/findings/{id}/',
        headers={
            'Authorization': f'Token {defectdojo_key}'
        },
        data={
          "verified": False,
          "active": False,
          "false_p": True,
        }
    ).json()


def add_note(id, note):
    return requests.post(
        url=f'{defectdojo_url}/api/v2/findings/{id}/notes',
        headers={
            'Authorization': f'Token {defectdojo_key}'
        },
        data={
            "entry": f'{note}',
            "private": False,
            "note_type": 0
        }
    ).json()


findings = get_findings()
changed = list()

for finding in findings.get('results'):
    for title_value in patterns:
        for description_value in patterns.get(title_value):
            if title_value in finding.get('title').lower():
                if description_value in finding.get('title').lower():
                    mark_as_false(
                        id=finding.get('id')
                    )
                    add_note(
                        id=finding.get('id'),
                        note='False Positive typical pattern'
                    )
                    changed.append(f'{defectdojo_url}/finding/{finding.get("id")}')

pprint(changed)

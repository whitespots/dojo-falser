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
        'integrity',
        '.git',
        '.lock'
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
            url=f'{defectdojo_url}/api/v2/findings/?duplicate=false&title=hard&limit=100&static_finding=true'
                f'&verified=false&false_p=false&is_mitigated=false&offset={offset}',
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
    )


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
    )


print('[Start] Getting vulnerabilities')
findings = get_findings()
print('[Done] Getting vulnerabilities')

changed = list()

print('[Start] Checking patterns')
for finding in findings.get('results'):
    for title_value in patterns:
        for description_value in patterns.get(title_value):
            if title_value in finding.get('title').lower():
                if description_value in finding.get('title').lower():
                    status = mark_as_false(
                        id=finding.get('id')
                    ).status_code
                    print(f'[{status}] Mark as FP')
                    status = add_note(
                        id=finding.get('id'),
                        note='False Positive typical pattern'
                    ).status_code
                    print(f'[{status}] Adding Note')
                    defectdojo_link = f'{defectdojo_url}/finding/{finding.get("id")}'
                    changed.append(defectdojo_link)
                    print(f'[FP No: {len(changed)}] {defectdojo_link}')
print('[Done] Checking patterns')
pprint(changed)


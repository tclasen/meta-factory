#!/usr/bin/env python3
"""Bounded synthetic native Projects fixture; creates only an assigned test project.

Default is a review plan, without GitHub calls. --execute requires the owner's
resource assignment. Retain the private project for review; never auto-delete.
No model, sbx, benchmark, holdout, credential or global-policy changes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.evidence import Attempt, atomic_json, collect, utc_now
from evaluation.git_state import render_git_seed
from evaluation.preparation import read_regular


class Fixture:
    def __init__(self, attempt, seconds, *, state_interface='project'):
        if state_interface not in ('project', 'graphql'):
            raise ValueError('Explicit native state interface required')
        self.attempt = attempt
        self.state_interface = state_interface
        self.deadline = time.monotonic() + seconds
        self.sequence = 0

    def command(self, label, argv, *, deadline=None):
        remaining = min(self.deadline, self.deadline if deadline is None else deadline) - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Projects fixture deadline expired')
        self.sequence += 1
        name = f'check-{self.sequence:03d}-{label}'
        result = collect(self.attempt, name, argv, cwd=ROOT,
                         timeout=min(30, remaining), max_output_bytes=1024 * 1024)
        if result['outcome'] != 'passed':
            raise RuntimeError('Native command failed; inspect retained check receipt')
        return (self.attempt.directory / name / 'stdout.log').read_text()

    def graphql(self, label, query, variables, *, deadline=None):
        # Credentials stay in gh's inherited authentication, never request/log data.
        request = self.attempt.directory / f'request-{self.sequence + 1:03d}.json'
        atomic_json(request, dict(query=query, variables=variables))
        data = json.loads(self.command(label, ['gh', 'api', 'graphql', '--input', str(request)], deadline=deadline))
        if data.get('errors') or not isinstance(data.get('data'), dict):
            raise RuntimeError('GraphQL returned errors or missing data')
        return data['data']

    def edit(self, project, item, field, *, option=None, text=None):
        if self.state_interface == 'graphql':
            value = {'singleSelectOptionId': option} if option else {'text': text}
            updated = self.graphql('native-graphql-item-edit', '''mutation($project: ID!,
              $item: ID!, $field: ID!, $value: ProjectV2FieldValue!) {
              updateProjectV2ItemFieldValue(input: {projectId: $project, itemId: $item,
                fieldId: $field, value: $value}) { projectV2Item { id } }
            }''', dict(project=project, item=item, field=field, value=value))
            if updated['updateProjectV2ItemFieldValue']['projectV2Item']['id'] != item:
                raise ValueError('Native update returned another item')
            return
        argv = ['gh', 'project', 'item-edit', '--project-id', project,
                '--id', item, '--field-id', field]
        argv += ['--single-select-option-id', option] if option else ['--text', text]
        self.command('native-item-edit', argv)

    def read_items(self, project, *, deadline=None):
        query = '''query($project: ID!, $after: String) {
          node(id: $project) { ... on ProjectV2 {
            items(first: 1, after: $after) { pageInfo { hasNextPage endCursor }
              nodes { id content { ... on DraftIssue { title body } }
                fieldValues(first: 100) { pageInfo { hasNextPage } nodes {
                  ... on ProjectV2ItemFieldTextValue { text field { ... on ProjectV2Field { name } } }
                  ... on ProjectV2ItemFieldSingleSelectValue { name optionId field {
                    ... on ProjectV2SingleSelectField { name } } }
                } }
              }
            }
          } }
        }'''
        result = {}; cursor = None; seen = set()
        # The reviewed workload has twelve packages. Keep one-item pages for
        # native pagination coverage; the bound matches the seed renderer's
        # maximum package count and remains subject to the request deadline.
        for _ in range(1000):
            data = self.graphql('paginated-read', query, dict(project=project, after=cursor), deadline=deadline)
            page = data['node']['items']
            for item in page['nodes']:
                if item['id'] in result or item['fieldValues']['pageInfo']['hasNextPage']:
                    raise ValueError('Duplicate item or incomplete field listing')
                fields = {}
                for field in item['fieldValues']['nodes']:
                    if 'field' in field:
                        name = field['field']['name']
                        if name in fields:
                            raise ValueError('Duplicate native field value')
                        fields[name] = field.get('text', field.get('name'))
                result[item['id']] = dict(content=item['content'], fields=fields)
            if not page['pageInfo']['hasNextPage']:
                return result
            cursor = page['pageInfo']['endCursor']
            if not cursor or cursor in seen:
                raise ValueError('Missing or repeated pagination cursor')
            seen.add(cursor)
        raise ValueError('Fixture pagination bound exceeded')

    def verify_items(self, project, expected):
        # Read retries reconcile service visibility; they never retry a mutation
        # or a failed command, switch an arm, or launch a replacement attempt.
        deadline = min(self.deadline, time.monotonic() + 15)
        while True:
            observed = self.read_items(project, deadline=deadline)
            matches = observed == expected
            self.attempt.emit('controller', 'projects.readback', dict(matches=matches))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Native readback did not settle within 15 seconds')
            if matches:
                return observed
            time.sleep(min(0.25, remaining))


def exercise(fixture, owner, report):
    report['gh_version'] = fixture.command('gh-version', ['gh', '--version']).strip()
    viewer = fixture.graphql('viewer', 'query { viewer { id login __typename } }', {})['viewer']
    if viewer['login'].lower() != owner.lower() or viewer['__typename'] != 'User':
        raise ValueError('Fixture requires the explicitly assigned authenticated user owner')
    report['owner'] = viewer['login']
    report['create_started'] = utc_now()
    atomic_json(fixture.attempt.directory / 'summary.json', report)
    project = fixture.graphql('create-owned-project', '''mutation($owner: ID!, $title: String!) {
      createProjectV2(input: {ownerId: $owner, title: $title}) {
        projectV2 { id number title public url } }
    }''', dict(owner=viewer['id'], title=report['project_title']))['createProjectV2']['projectV2']
    report['project'] = project
    report['cleanup'] = dict(outcome='retained_for_owner_review',
        delete_argv=['gh', 'project', 'delete', str(project['number']), '--owner', owner],
        note='Delete only after evidence review and separate owner authorization.')
    atomic_json(fixture.attempt.directory / 'summary.json', report)
    if project['public'] or project['title'] != report['project_title']:
        raise ValueError('Private uniquely named project required')
    fields = fixture.graphql('read-fields', '''query($project: ID!) {
      node(id: $project) { ... on ProjectV2 { fields(first: 100) {
        pageInfo { hasNextPage } nodes {
          ... on ProjectV2Field { id name }
          ... on ProjectV2SingleSelectField { id name options { id name } }
        } } } }
    }''', dict(project=project['id']))['node']['fields']
    if fields['pageInfo']['hasNextPage']:
        raise ValueError('Unexpected truncated initial field listing')
    matches = [field for field in fields['nodes'] if field.get('name') == 'Status']
    if len(matches) != 1 or 'options' not in matches[0]:
        raise ValueError('Unique native single-select Status required')
    status = matches[0]
    updated = fixture.graphql('configure-status', '''mutation($field: ID!,
      $options: [ProjectV2SingleSelectFieldOptionInput!]) {
      updateProjectV2Field(input: {fieldId: $field, singleSelectOptions: $options}) {
        projectV2Field { ... on ProjectV2SingleSelectField { id options { id name } } }
      }
    }''', dict(field=status['id'], options=[dict(name=name, color=color, description=name)
        for name, color in [('Todo', 'GRAY'), ('In progress', 'BLUE'),
                            ('Blocked', 'RED'), ('Done', 'GREEN')]]))['updateProjectV2Field']['projectV2Field']
    options = {option['name']: option['id'] for option in updated['options']}
    if set(options) != {'Todo', 'In progress', 'Blocked', 'Done'}:
        raise ValueError('Native status options do not match the proposed treatment')
    identities = {'Status': status['id']}
    for name in ('Work package', 'Progress', 'Next action'):
        field = fixture.graphql('create-text-field', '''mutation($project: ID!, $name: String!) {
          createProjectV2Field(input: {projectId: $project, name: $name, dataType: TEXT}) {
            projectV2Field { ... on ProjectV2Field { id name } }
          }
        }''', dict(project=project['id'], name=name))['createProjectV2Field']['projectV2Field']
        identities[name] = field['id']
    report['fields'] = identities; report['status_options'] = options
    expected = {}; items = []
    packages = report.get('seed_packages', [('WP-001', 'Synthetic foundation'), ('WP-002', 'Synthetic follow-up')])
    for identifier, title in packages:
        identity = report.get('packages_manifest_sha256', 'synthetic-v1')
        content = dict(title=f'{identifier} — {title}', body=f'Synthetic native fixture manifest {identity}: {identifier}')
        item = fixture.graphql('seed-draft-item', '''mutation($project: ID!, $title: String!, $body: String!) {
          addProjectV2DraftIssue(input: {projectId: $project, title: $title, body: $body}) {
            projectItem { id }
          }
        }''', dict(project=project['id'], **content))['addProjectV2DraftIssue']['projectItem']['id']
        items.append(item)
        fixture.edit(project['id'], item, identities['Work package'], text=identifier)
        fixture.edit(project['id'], item, identities['Status'], option=options['Todo'])
        expected[item] = dict(content=content, fields={'Title': content['title'], 'Work package': identifier, 'Status': 'Todo'})
    report['items'] = items
    atomic_json(fixture.attempt.directory / 'summary.json', report)
    def verify():
        return fixture.verify_items(project['id'], expected)
    report['initial_state'] = verify()
    atomic_json(fixture.attempt.directory / 'initial-state.json', report['initial_state'])
    for index, state in enumerate(('In progress', 'Blocked', 'In progress', 'Done', 'In progress'), 1):
        item = items[0]
        # Deliberately split fields: verify partial persistence before reconciliation.
        fixture.edit(project['id'], item, identities['Status'], option=options[state])
        expected[item]['fields']['Status'] = state
        verify()
        for name, value in [('Progress', f'Synthetic public finding {index}'),
                            ('Next action', f'Synthetic next action {index}')]:
            fixture.edit(project['id'], item, identities[name], text=value)
            expected[item]['fields'][name] = value
        verify()
    report['final_state'] = verify()
    report['outcome'] = 'synthetic_native_projects_passed'
    report['credential_limits'] = 'Observed access only; no claim of per-project credential isolation.'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', required=True, help='Explicitly assigned authenticated GitHub user')
    parser.add_argument('--execute', action='store_true', help='Create the assigned disposable private fixture')
    parser.add_argument('--state-interface', choices=('project', 'graphql'), default='project',
                        help='Explicit native edit interface; never switch automatically on failure')
    parser.add_argument('--package-manifest', type=Path, help='Exact reviewed packages.json for workload-sized synthetic seeding')
    parser.add_argument('--packages-sha256', help='Expected packages.json hash from the human workload review')
    args = parser.parse_args(argv)
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9-]{0,38}', args.owner):
        parser.error('Ordinary GitHub user login required')
    planning = ROOT / '.factory-planning' / 'projects-state-logs'
    planning.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=planning)) / 'attempt'
    print(f'Evidence directory: {directory}', flush=True)
    report = dict(started=utc_now(), outcome='planned_not_executed', owner=args.owner,
        state_interface=args.state_interface,
        project_title='factory-req007-fixture-' + directory.parent.name,
        changes='One private synthetic project, fields and two draft items; retained for review.',
        cleanup=dict(outcome='no_resource_created'),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        limitations='Synthetic Projects workflow only; no model/sbx/benchmark/compaction/approval/promotion evidence.')
    status = 0
    with Attempt(directory, dict(owner=args.owner, execute=args.execute)) as attempt:
        try:
            fixture = Fixture(attempt, 600, state_interface=args.state_interface)
            report['tested_revision'] = fixture.command('revision', ['git', 'rev-parse', 'HEAD']).strip()
            if fixture.command('worktree', ['git', 'status', '--porcelain']):
                raise ValueError('Clean committed worktree required')
            if (args.package_manifest is None) != (args.packages_sha256 is None):
                raise ValueError('Package manifest and reviewed expected hash must be supplied together')
            if args.package_manifest is not None:
                raw = read_regular(args.package_manifest, 1024 * 1024, lambda: None)
                render_git_seed(raw, args.packages_sha256)  # Reuse the exact Git seed identity/schema validation.
                manifest = json.loads(raw)
                report['seed_packages'] = [(p['id'], p['title']) for p in manifest['packages']]
                report['packages_manifest_sha256'] = args.packages_sha256
                report['specification_version'] = manifest['specification_version']
                report['changes'] = f'One private synthetic project with {len(report["seed_packages"])} reviewed-package draft items; retained for review.'
            if args.execute:
                report['outcome'] = 'synthetic_native_projects_incomplete'
                exercise(fixture, args.owner, report)
        except BaseException as error:
            status = 1
            report.update(outcome='synthetic_native_projects_incomplete', error_type=type(error).__name__)
            if report.get('create_started') and not report.get('project'):
                report['cleanup'] = dict(outcome='creation_uncertain_find_by_unique_title',
                    owner=args.owner, title=report['project_title'])
        finally:
            report.update(ended=utc_now(), exit_status=status)
            atomic_json(directory / 'summary.json', report)
            print(f'Evidence directory: {directory}\nOutcome: {report["outcome"]}', flush=True)
    return status


if __name__ == '__main__':
    sys.exit(main())

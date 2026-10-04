"""Inventory source inside a readonly sandbox, then capture after verified stop."""

import os
from pathlib import Path
import tempfile

from .evidence import atomic_json, collect
from .sandbox import Sandbox, capture_tree
from .watchdog import Guard


def parse_paths(data):
    if data and not data.endswith(b'\0'):
        raise ValueError('Truncated Git path inventory')
    names = set()
    for raw in data.split(b'\0')[:-1]:
        name = raw.decode('utf-8', errors='strict')
        path = Path(name)
        if (not name or path.is_absolute() or '..' in path.parts or str(path) != name
                or path.parts[0] == '.git'):
            raise ValueError('Unsafe Git inventory path')
        names.add(name)
    return names


def capture_source(attempt, source, destination, specification, *, port,
                   termination_verified, sandbox_factory=Sandbox,
                   guard_factory=Guard, command_runner=collect):
    """Preserve tracked and nonignored untracked files plus regular Git metadata.

    Ignored artifacts and tracked deletions have explicit retained inventories.
    Git runs only in a separate readonly shell sandbox, never on the host or in
    the stopped builder. Linked worktrees, selected symlinks and hardlinks remain
    capture-incomplete until independently supported. Missing build inputs become
    visible during redeployment; this is not proof of build reproducibility.
    """
    if termination_verified is not True:
        raise ValueError('Builder termination must be verified before inventory')
    source = Path(source).resolve(strict=True)
    git = source / '.git'
    if git.is_symlink() or not git.is_dir():
        raise ValueError('Capture requires an ordinary repository, not a linked worktree')
    repository = Path(__file__).resolve().parents[1]
    # sbx 0.46.0 requires a writable primary workspace; retain this empty scratch
    # workspace for diagnosis and mount the actual project separately readonly.
    scratch = Path(tempfile.mkdtemp(prefix='factory-source-inventory-')).resolve()
    atomic_json(attempt.directory / 'inventory-workspace.json', {'retained_scratch': str(scratch)})
    box = sandbox_factory(attempt, source, specification, repository, port=port,
                          role='grader', project_readonly=True, primary_workspace=scratch)
    guard = None
    selection = None
    cleanup = {'remote_termination_verified': False}
    try:
        if box.create()['outcome'] != 'passed':
            raise RuntimeError('Source inventory sandbox creation failed')
        guard = guard_factory(attempt.directory / 'inventory-guard', box.name, max_seconds=240)
        inventories = {}
        # ls-files does not run hooks; explicitly disable configured fsmonitor and
        # isolate system/global config. Repository ignore rules remain deliberate.
        prefix = ['env', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null',
                  'GIT_OPTIONAL_LOCKS=0', 'git', '-c', 'core.fsmonitor=false',
                  '-c', 'core.excludesFile=/dev/null', '-c', 'safe.directory=' + str(source),
                  'ls-files', '-z']
        modes = {'selected': ['--cached', '--others', '--exclude-standard'],
                 'ignored': ['--others', '--ignored', '--exclude-standard'],
                 'deleted': ['--deleted']}
        for label, arguments in modes.items():
            result = command_runner(attempt, 'inventory-' + label, box.exec_argv(prefix + arguments),
                                    cwd=repository, timeout=60)
            if result['outcome'] != 'passed':
                raise RuntimeError('Source inventory command did not complete')
            inventories[label] = parse_paths((attempt.directory / ('inventory-' + label) / 'stdout.log').read_bytes())
        selected = inventories['selected'] - inventories['deleted']
        # Git metadata is evidence and permits normal sandbox-local Git operations
        # after redeployment. Never run its hooks/configuration on the host.
        for root, directories, files in os.walk(git, followlinks=False):
            for name in directories:
                if (Path(root) / name).is_symlink():
                    raise ValueError('Symlink in Git metadata')
            selected.update(str((Path(root) / name).relative_to(source)) for name in files)
        selection = {'method': 'git-tracked-and-untracked-nonignored-plus-git-metadata',
                     'selected': sorted(selected), 'ignored': sorted(inventories['ignored']),
                     'deleted': sorted(inventories['deleted'])}
        atomic_json(attempt.directory / 'source-selection.json', selection)
    finally:
        if guard is not None:
            try:
                cleanup = guard.release()
                box.stopped = cleanup.get('remote_termination_verified') is True
            except Exception as error:
                cleanup['error_type'] = type(error).__name__
        if box.creation_attempted and not box.stopped:
            try:
                cleanup['remote_termination_verified'] = box.stop()
            except Exception as error:
                cleanup.update(remote_termination_verified=False,
                               fallback_error_type=type(error).__name__)
        atomic_json(attempt.directory / 'inventory-cleanup.json', cleanup)
    if not cleanup.get('remote_termination_verified'):
        raise RuntimeError('Inventory sandbox termination unverified')
    inventory = capture_tree(source, destination, termination_verified=True,
                             selected_files=selection['selected'])
    inventory['selection'] = selection
    atomic_json(attempt.directory / 'source-capture.json', inventory)
    return inventory

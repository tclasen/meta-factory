"""Scoped sbx resources and capture after independently verified termination."""

import hashlib
import os
from pathlib import Path
import posixpath
import stat
import uuid

from .evidence import atomic_json, collect


def disjoint(*paths):
    resolved = [Path(path).resolve() for path in paths]
    for index, left in enumerate(resolved):
        for right in resolved[index + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise ValueError("Project, specification, evidence and controller paths must be disjoint")
    return resolved


def stopped_from_listing(text, name):
    """Pinned sbx 0.46.0 table; never use exec to check a stopped sandbox."""
    rows = text.splitlines()
    if not rows or rows[0].split()[:3] != ["SANDBOX", "AGENT", "STATUS"]:
        return False
    matches = [line.split() for line in rows[1:] if line.split() and line.split()[0] == name]
    return len(matches) == 1 and len(matches[0]) >= 3 and matches[0][2] == "stopped"


class Sandbox:
    def __init__(self, attempt, project, specification, controller, *, port, role="builder",
                 project_readonly=False, primary_workspace=None):
        if role not in ("builder", "grader") or isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError("Invalid sandbox role/port")
        self.project_readonly = bool(project_readonly)
        self.project, self.specification = disjoint(project, specification)
        self.primary_workspace = Path(primary_workspace).resolve() if primary_workspace else None
        if self.project_readonly != (self.primary_workspace is not None):
            raise ValueError("Readonly projects require a separate writable primary workspace")
        mounts = [self.project, self.specification]
        if self.primary_workspace is not None:
            disjoint(self.primary_workspace, self.project, self.specification)
            mounts.append(self.primary_workspace)
        for mount in mounts:
            for protected in (attempt.directory, controller):
                disjoint(mount, protected)
        if not all(mount.is_dir() for mount in mounts):
            raise ValueError("Workspace and specification directories must exist")
        if any(":" in str(p) for p in mounts):
            raise ValueError("Mount paths cannot contain sbx mode separators")
        self.attempt, self.port, self.role = attempt, port, role
        self.name = f"factory-eval-{role}-{uuid.uuid4().hex[:16]}"
        self.creation_attempted = False
        self.stopped = False

    def create_argv(self):
        mounts = ([str(self.primary_workspace)] if self.primary_workspace else [])
        mounts += [str(self.project) + (":ro" if self.project_readonly else ""), str(self.specification) + ":ro"]
        return ["sbx", "create", "--name", self.name, "--cpus", "8", "--memory", "16g",
                "--skills", "off", "--publish", f"127.0.0.1:{self.port}:8080",
                "codex" if self.role == "builder" else "shell", *mounts]

    def create(self):
        if self.creation_attempted:
            raise ValueError("Sandbox creation cannot be retried in this attempt")
        self.creation_attempted = True
        atomic_json(self.attempt.directory / f"{self.role}-resource.json", {
            "name": self.name, "project": str(self.project), "specification": str(self.specification),
            "primary_workspace": str(self.primary_workspace) if self.primary_workspace else None,
            "project_readonly": self.project_readonly,
            "port": self.port, "manual_stop": ["sbx", "stop", self.name], "cleanup": "pending"})
        return collect(self.attempt, f"{self.role}-create", self.create_argv(), cwd=self.project, timeout=300)

    def exec_argv(self, command, *, interactive=False):
        if not command or not all(isinstance(arg, str) for arg in command):
            raise ValueError("Invalid sandbox command")
        if self.stopped:
            raise ValueError("exec would restart the captured sandbox")
        return ["sbx", "exec"] + (["-i"] if interactive else []) + ["-w", str(self.project), self.name] + command

    def stop(self):
        if not self.creation_attempted:
            raise ValueError("Refusing to stop a resource not created by this adapter")
        result = collect(self.attempt, f"{self.role}-stop", ["sbx", "stop", self.name], cwd=self.project, timeout=60)
        listing = collect(self.attempt, f"{self.role}-stopped-check", ["sbx", "ls"], cwd=self.project, timeout=30)
        text = (self.attempt.directory / f"{self.role}-stopped-check/stdout.log").read_text()
        self.stopped = result["outcome"] == "passed" and listing["outcome"] == "passed" and stopped_from_listing(text, self.name)
        atomic_json(self.attempt.directory / f"{self.role}-cleanup.json", {
            "name": self.name, "stop": result, "verification": listing,
            "remote_termination_verified": self.stopped, "manual_stop": ["sbx", "stop", self.name]})
        return self.stopped


def symlink_record(source, path):
    """Relative links may survive relocation only if they stay within the source."""
    target = os.readlink(path)
    if os.path.isabs(target):
        raise ValueError("Absolute symlink cannot safely relocate")
    lexical = posixpath.normpath(str(path.parent.relative_to(source) / target))
    if lexical == '..' or lexical.startswith('../'):
        raise ValueError("Symlink lexically escapes captured project")
    try:
        resolved = (path.parent / target).resolve()
    except RuntimeError as error:
        raise ValueError("Cyclic source symlink") from error
    if resolved != source and source not in resolved.parents:
        raise ValueError("Symlink escapes captured project")
    encoded = target.encode('utf-8')
    return {'kind': 'symlink', 'target': target, 'sha256': hashlib.sha256(encoded).hexdigest(),
            'size': len(encoded), 'executable': False}


def capture_identity(value):
    # Reads may update atime, but ownership/mode/link/content metadata must stay
    # fixed across the snapshot. ctime detects rewrites that restore mtime.
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_mode, value.st_nlink, value.st_uid, value.st_gid)


def capture_tree(source, destination, *, termination_verified, max_bytes=2 * 1024**3, max_files=100000, selected_files=None):
    """Copy source bytes and safe relative links; never execute Git/build/hooks.

    Escaping links/special files/hardlinks are capture-incomplete, not application failure.
    Caller must include all source, Git metadata and required build assets; no
    implicit ignore rules silently omit application inputs. An explicit source
    selection may omit inventoried generated artifacts. Relative source symlinks
    are preserved as links and never traversed by the host copier.
    """
    if termination_verified is not True:
        raise ValueError("Remote termination must be verified before capture")
    if type(max_bytes) is not int or type(max_files) is not int or min(max_bytes, max_files) <= 0:
        raise ValueError("Invalid capture bounds")
    source = Path(source).resolve(strict=True)
    destination = Path(destination).resolve()
    disjoint(source, destination)
    selected = None
    selected_directories = set()
    if selected_files is not None:
        selected = set(selected_files)
        if len(selected) > max_files:
            raise ValueError("Capture file limit exceeded")
        for name in selected:
            path = Path(name)
            if (not isinstance(name, str) or not path.parts or path.is_absolute()
                    or ".." in path.parts or str(path) != name):
                raise ValueError("Invalid selected source path")
            full = source / path
            if any(p.is_symlink() for p in full.parents if p != source and source in p.parents):
                raise ValueError("Symlink parent in selected source path")
            if full.is_symlink():
                symlink_record(source, full)
            elif not full.is_file():
                raise ValueError("Selected source file missing or non-regular")
            selected_directories.update(str(parent) for parent in path.parents)
    destination.mkdir(mode=0o700)
    inventory = {}
    total = 0
    def copy_link(path, relative):
        nonlocal total
        before = path.lstat()
        record = symlink_record(source, path)
        if len(inventory) >= max_files or total + record['size'] > max_bytes:
            raise ValueError("Capture size limit exceeded")
        os.symlink(record['target'], destination / relative)
        after = path.lstat()
        if capture_identity(before) != capture_identity(after):
            raise ValueError("Symlink changed during capture")
        inventory[str(relative)] = record
        total += record['size']
    try:
        for root, directories, files in os.walk(source, followlinks=False):
            relative = Path(root).relative_to(source)
            if selected is not None:
                directories[:] = [name for name in directories
                                  if str(relative / name) in selected_directories or str(relative / name) in selected]
                files = [name for name in files if str(relative / name) in selected]
            for name in directories:
                path = Path(root) / name
                if path.is_symlink():
                    copy_link(path, relative / name)
                else:
                    (destination / relative / name).mkdir(mode=0o700)
            for name in files:
                path = Path(root) / name
                before = path.lstat()
                if stat.S_ISLNK(before.st_mode):
                    copy_link(path, relative / name)
                    continue
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise ValueError("Non-regular or hardlinked file in capture")
                if len(inventory) >= max_files or total + before.st_size > max_bytes:
                    raise ValueError("Capture size limit exceeded")
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    current = os.fstat(descriptor)
                    if capture_identity(current) != capture_identity(before):
                        raise ValueError("Source changed during capture")
                    target = destination / relative / name
                    out_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700 if before.st_mode & 0o111 else 0o600)
                    digest = hashlib.sha256()
                    size = 0
                    with os.fdopen(out_fd, "wb") as out:
                        while chunk := os.read(descriptor, 65536):
                            size += len(chunk)
                            if total + size > max_bytes or size > before.st_size:
                                raise ValueError("Source grew during capture")
                            out.write(chunk)
                            digest.update(chunk)
                    after = os.fstat(descriptor)
                    if size != before.st_size or capture_identity(after) != capture_identity(before):
                        raise ValueError("Source changed during capture")
                    inventory[str(relative / name)] = {"sha256": digest.hexdigest(), "size": size,
                                                       "executable": bool(before.st_mode & 0o111)}
                    total += size
                finally:
                    os.close(descriptor)
        if selected is not None and set(inventory) != selected:
            raise ValueError("Selected source changed during capture")
        return {"files": inventory, "bytes": total, "outcome": "captured"}
    except BaseException:
        # Partial bytes are retained for diagnosis; never relabel as a full capture.
        raise

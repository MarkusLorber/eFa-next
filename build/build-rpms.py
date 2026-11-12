#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Build the eFa-next-base and eFa-next RPMs and a SHA256SUMS file.

    build/build-rpms.py [--next-dir DIR] [--out DIR]

--next-dir: folder with the eFa-next programs (efactl, efa-web.py,
efa-init.py, ...) laid out like the target file system; packaged into eFa.
The source archives get fixed owners, modes and times, and rpmbuild runs
with a neutral _buildhost, so the build host name is not in the RPMs. Files
made during the build get the time of SOURCE_DATE_EPOCH too: the same source
gives the same RPMs (Q4). An SBOM (CycloneDX JSON) goes next to them.
"""

import argparse
import glob
import gzip
import hashlib
import io
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOP = os.path.dirname(HERE)
BUILD_HOST = "localhost"
EXEC_DIRS = ("usr/sbin/", "usr/bin/", "usr/libexec/", "usr/local/sbin/")


def spec_version(spec):
    with open(spec, encoding="utf-8") as fh:
        match = re.search(r"^Version:\s*(\S+)", fh.read(), re.M)
    if not match:
        sys.exit("no Version in %s" % spec)
    return match.group(1)


def build_requires(spec):
    """The BuildRequires of a spec, names only (without version)."""
    with open(spec, encoding="utf-8") as fh:
        return re.findall(r"^BuildRequires:\s*([^\s,]+)", fh.read(), re.M)


def missing_build_requires(specs, installed=None):
    """What rpmbuild would stop at, asked before: rpm -q --whatprovides for each BuildRequires."""
    installed = installed or (lambda name: subprocess.run(["rpm", "-q", "--whatprovides", name], capture_output=True).returncode == 0)
    return sorted({name for spec in specs for name in build_requires(spec) if not installed(name)})


def add_tree(tar, source, prefix, mtime):
    """Add a folder with normalised metadata (root owner, 0755/0644)."""
    for folder, dirs, files in os.walk(source):
        dirs.sort()
        rel_dir = os.path.relpath(folder, source)
        for name in [None] + sorted(files):
            path = folder if name is None else os.path.join(folder, name)
            rel = rel_dir if name is None else os.path.normpath(os.path.join(rel_dir, name))
            if name is not None and (name == "__pycache__" or name.endswith(".pyc")):
                continue
            if "__pycache__" in rel.split(os.sep):
                continue
            info = tarfile.TarInfo(prefix + ("" if rel == "." else "/" + rel))
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = mtime
            if name is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
                continue
            target = rel.replace(os.sep, "/")
            executable = target.startswith(EXEC_DIRS)
            info.mode = 0o755 if executable else 0o644
            with open(path, "rb") as fh:
                data = fh.read()
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def make_source(name, version, parts, sources_dir, mtime):
    prefix = "%s-%s" % (name, version)
    out = os.path.join(sources_dir, prefix + ".tar.gz")
    # The gzip header holds a time as well.
    with open(out, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=mtime, filename="") as packed, \
            tarfile.open(fileobj=packed, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for source, sub in parts:
            add_tree(tar, source, prefix + "/" + sub, mtime)
    return out


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--next-dir", help="eFa-next programs as a root tree")
    ap.add_argument("--out", default=os.path.join(TOP, "dist"))
    args = ap.parse_args()
    specs = {n: os.path.join(TOP, "rpm", n + ".spec") for n in ("eFa-base", "eFa")}
    versions = {spec_version(p) for p in specs.values()}
    if len(versions) != 1:
        sys.exit("eFa-base.spec and eFa.spec must have the same Version")
    version = versions.pop()
    missing = missing_build_requires(specs.values())
    if missing:
        sys.exit("missing build tools: %s\ninstall them first: dnf -y install dnf-plugins-core && dnf -y builddep %s"
                 % (" ".join(missing), " ".join(os.path.relpath(p) for p in specs.values())))
    # The SBOM after the build checks against the official schema: missing, the build would stop at its very end.
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        sys.exit("missing build tool: python3-jsonschema (AlmaLinux AppStream): dnf -y install python3-jsonschema")
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH", "1767225600"))
    top = tempfile.mkdtemp(prefix="efa-rpmbuild-")
    try:
        for sub in ("SOURCES", "SPECS", "BUILD", "RPMS", "SRPMS"):
            os.makedirs(os.path.join(top, sub))
        src = os.path.join(TOP, "src")
        # The specs keep their file names; the packages and their sources are eFa-next-base and eFa-next.
        make_source("eFa-next-base", version,
                    [(os.path.join(src, "eFa-base", "root"), "root"),
                     (os.path.join(src, "eFa-base", "selinux"), "selinux")],
                    os.path.join(top, "SOURCES"), mtime)
        parts = [(os.path.join(src, "eFa", "root"), "root")]
        if args.next_dir:
            parts.append((os.path.abspath(args.next_dir), "next"))
            # 5y: the legal texts with their digest and as PDF, made here so the package carries the ones of this source.
            sys.path.insert(0, os.path.join(os.path.abspath(args.next_dir), "usr", "lib", "eFa", "python"))
            import efa_legal
            legal = os.path.join(top, "legal")
            efa_legal.build(TOP, os.path.join(legal, efa_legal.FOLDER.lstrip("/")), version)
            parts.append((legal, "next"))
        else:
            print("warning: no --next-dir: eFa is built without the eFa-next programs")
        make_source("eFa-next", version, parts, os.path.join(top, "SOURCES"), mtime)
        for name in ("eFa-base", "eFa"):
            subprocess.run(["rpmbuild", "-bb",
                            "--define", "_topdir " + top,
                            "--define", "_buildhost " + BUILD_HOST,
                            "--define", "use_source_date_epoch_as_buildtime 1",
                            "--define", "clamp_mtime_to_source_date_epoch 1",
                            specs[name]], check=True,
                           env=dict(os.environ, SOURCE_DATE_EPOCH=str(mtime)))
        os.makedirs(args.out, exist_ok=True)
        # RPMS/noarch/ as rpmbuild lays it out, or RPMS/ directly (the ~/.rpmmacros of mock): both.
        rpms = sorted(glob.glob(os.path.join(top, "RPMS", "**", "*.rpm"), recursive=True))
        if not rpms:
            sys.exit("rpmbuild made no packages in %s" % os.path.join(top, "RPMS"))
        local = socket.gethostname()
        lines = []
        for rpm in rpms:
            host = subprocess.run(["rpm", "-qp", "--qf", "%{BUILDHOST}", rpm],
                                  check=True, stdout=subprocess.PIPE,
                                  universal_newlines=True).stdout.strip()
            if host != BUILD_HOST or (local not in ("", BUILD_HOST) and local in host):
                sys.exit("build host name found in %s" % rpm)
            dest = os.path.join(args.out, os.path.basename(rpm))
            shutil.copy2(rpm, dest)
            lines.append("%s  %s\n" % (sha256(dest), os.path.basename(rpm)))
        bom = os.path.join(args.out, "eFa-next-%s.cdx.json" % version)
        subprocess.run([sys.executable, "-I", os.path.join(HERE, "sbom.py"), "--out", bom] +
                       [os.path.join(args.out, os.path.basename(rpm)) for rpm in rpms], check=True,
                       env=dict(os.environ, SOURCE_DATE_EPOCH=str(mtime)))
        lines.append("%s  %s\n" % (sha256(bom), os.path.basename(bom)))
        with open(os.path.join(args.out, "SHA256SUMS"), "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        print("built %d packages in %s" % (len(rpms), args.out))
    finally:
        shutil.rmtree(top, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

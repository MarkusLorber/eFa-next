# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Tests for the service monitor and static checks of the package files."""

import os
import re
import unittest

from efa_testlib import TOP, RootTestCase, c

import efa_monitor

SETTINGS = 'SERVICES="postfix clamd@scan"\nMAX_RESTARTS=2\nCOUNTER_MINUTES=10\n'


class MonitorTests(RootTestCase):
    def setUp(self):
        super().setUp()
        self.write("etc/sysconfig/eFa-Monitor", SETTINGS)
        c.write_kv("/etc/eFa/eFa-Config", {"ADMINEMAIL": "admin@example.org"}, 0o640)

    def restarts(self):
        return [cmd[2] for cmd in self.runner.calls if cmd[:2] == ["systemctl", "restart"]]

    def mails(self):
        return [inp for cmd, inp in zip(self.runner.calls, self.runner.inputs)
                if cmd[0].endswith("sendmail")]

    def test_restart_limit_and_one_mail(self):
        self.runner.active.add("postfix")
        for minute in range(5):
            self.runner.active.discard("clamd@scan")  # stays down
            efa_monitor.check(now=1000 + 60 * minute)
        self.assertEqual(self.restarts(), ["clamd@scan", "clamd@scan"])
        self.assertEqual(len(self.mails()), 1)
        self.assertIn("To: admin@example.org", self.mails()[0])

    def test_counter_expires(self):
        self.runner.active.add("postfix")
        for now in (0, 60, 120):
            self.runner.active.discard("clamd@scan")
            efa_monitor.check(now=now)
        self.runner.active.discard("clamd@scan")
        efa_monitor.check(now=601)
        self.assertEqual(len(self.restarts()), 3)

    def test_enable_disable(self):
        efa_monitor.enable()
        self.assertIn("* * * * * root /usr/sbin/efa-monitor",
                      self.read("etc/cron.d/eFa-Monitor.cron"))
        efa_monitor.disable()
        self.assertFalse(os.path.exists(self.path("etc/cron.d/eFa-Monitor.cron")))

    def test_reboot_check(self):
        self.assertTrue(efa_monitor.reboot_check())
        self.assertTrue(os.path.exists(self.path("var/lib/eFa/reboot-due")))


class PackagingTests(unittest.TestCase):
    def files(self):
        skip = {"dist", "__pycache__"}
        for top in ("build", "rpm", "src", "tests"):
            for folder, dirs, names in os.walk(os.path.join(TOP, top)):
                dirs[:] = [d for d in dirs if d not in skip]
                for name in names:
                    if not name.endswith((".pyc",)):
                        yield os.path.join(folder, name)

    def test_spdx_headers_and_no_attribution(self):
        words = ["cla" + "ude", "anthr" + "opic"]  # split so this file passes too
        banned = re.compile(r"\b(%s)\b|generated (by|with) (an )?ai" % "|".join(words), re.I)
        for path in self.files():
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("SPDX-License-Identifier: AGPL-3.0-or-later", text[:300], path)
            self.assertIn("Copyright (C) 2026 Markus Lorber and eFa-next contributors", text[:400], path)
            self.assertIn("Author: Markus Lorber, Lukasz Galusinski", text[:400], path)
            self.assertIsNone(banned.search(text), path)

    def test_specs(self):
        for name in ("eFa-base", "eFa"):
            with open(os.path.join(TOP, "rpm", name + ".spec"), encoding="utf-8") as fh:
                spec = fh.read()
            self.assertIn("%global _buildhost localhost", spec)
            self.assertIn("/etc/MailScanner/MailScanner.conf", spec.split("%posttrans")[0])
            self.assertRegex(spec, r"Version:\s+6\.0\.0\.\d+")
            self.assertNotRegex(spec, r"Requires:\s*(httpd|php|perl)")
        # Both packages carry the same version, or the dependency eFa-base = %{version} breaks.
        versions = set()
        for name in ("eFa-base", "eFa"):
            with open(os.path.join(TOP, "rpm", name + ".spec"), encoding="utf-8") as fh:
                versions.add(re.search(r"Version:\s+(\S+)", fh.read()).group(1))
        self.assertEqual(len(versions), 1, versions)
        with open(os.path.join(TOP, "rpm", "eFa.spec"), encoding="utf-8") as fh:
            spec = fh.read()
        self.assertIn("Requires:       eFa-next-base = 1:%{version}-%{release}", spec)
        # The packages replace eFa and eFa-base of 6.0.0.4; without the epoch 1:6.0.0.4 of eFa-base is not older.
        self.assertIn("Obsoletes:      eFa < 6.0.0.4.1", spec)
        with open(os.path.join(TOP, "rpm", "eFa-base.spec"), encoding="utf-8") as fh:
            self.assertIn("Obsoletes:      eFa-base < 1:6.0.0.4.1", fh.read())

    def test_bytecode_compiled_by_hash_before_the_setup(self):
        """Both packages compile /usr/lib/eFa/python by the hash of the source before their setup, and remove __pycache__ on erase."""
        for spec_name, setup in (("eFa.spec", "/usr/lib/eFa/setup/efa-next-setup"), ("eFa-base.spec", "/usr/sbin/efa-configure")):
            with open(os.path.join(TOP, "rpm", spec_name), encoding="utf-8") as fh:
                spec = fh.read()
            posttrans = spec.split("%posttrans", 1)[1].split("%preun", 1)[0]
            self.assertIn("compileall -q -f --invalidation-mode checked-hash /usr/lib/eFa/python", posttrans, spec_name)
            self.assertLess(posttrans.index("compileall"), posttrans.index(setup), spec_name)
            self.assertIn("rm -rf /usr/lib/eFa/python/__pycache__", spec.split("%preun", 1)[1].split("%postun", 1)[0], spec_name)

    def test_installer_installs_its_own_tools_first(self):
        """build.bash on a minimal EL9: the first step names and installs what it lacks (git only for source)."""
        import shutil
        import subprocess
        if not shutil.which("bash"):
            self.skipTest("no bash")
        with open(os.path.join(TOP, "build", "build.bash"), encoding="utf-8") as fh:
            script = fh.read()
        self.assertLess(script.index('step "install the tools of the installer" preflight'), script.index('step "check the operating system'))
        part = script[script.index("PREFLIGHT_TOOLS="):script.index("check_os() {")]
        stubs = ('rpm() { case "$2" in git-core|chrony) return 1;; esac; }\ndnf() { echo "dnf $*"; }\n'
                 'systemctl() { :; }\ngetent() { :; }\nchronyc() { return 1; }\n')
        for action, wanted in (("source", "dnf -y install chrony git-core"), ("production", "dnf -y install chrony")):
            out = subprocess.run(["bash", "-c", f"ACTION={action}\n{stubs}{part}\npreflight"], capture_output=True, text=True, check=True).stdout
            self.assertIn("missing, installed now:", out, action)
            self.assertIn("WARNING: the clock is not synchronized", out, "an unsynchronized clock is named, the install goes on")
            self.assertEqual([line for line in out.splitlines() if line.startswith("dnf")], [wanted], action)

    def test_no_chronyc_in_package_scripts(self):
        """chronyc from a package script gets no answer from chronyd under SELinux (rpm_script_t): the unit efa-time-sync does it."""
        with open(os.path.join(TOP, "src", "eFa-base", "root", "usr", "lib", "eFa", "python", "efa_configure.py"), encoding="utf-8") as fh:
            configure = fh.read()
        self.assertNotIn(".time_sync()", configure)
        self.assertIn('service_start_background("efa-time-sync.service")', configure)
        with open(os.path.join(TOP, "rpm", "eFa-base.spec"), encoding="utf-8") as fh:
            self.assertIn("/usr/lib/systemd/system/efa-time-sync.service", fh.read())

    def test_build_tools_removed_without_efa_next(self):
        """build.bash source: only what the build added and eFa-next does not need goes, by rpm -e; on doubt everything stays."""
        import shutil
        import subprocess
        import tempfile
        if not shutil.which("bash") or not shutil.which("comm"):
            self.skipTest("no bash")
        with open(os.path.join(TOP, "build", "build.bash"), encoding="utf-8") as fh:
            script = fh.read()
        self.assertNotIn("dnf -y autoremove", script, "autoremove took eFa-next and its runtime along")
        part = script[script.index("BUILD_ONLY="):script.index("install_rpms() {")]
        for test_ok, expect_removed in ((0, "rpm -e perl-Git redhat-rpm-config rpm-build"), (1, None)):
            with tempfile.TemporaryDirectory() as folder:
                log = folder.replace(os.sep, "/")
                with open(os.path.join(folder, "before-build-tools.txt"), "w") as fh:
                    fh.write("bash\ncurl\n")
                # builddep brings runtime packages (postfix, rspamd, flask, perl of rspamd) next to the build tools.
                installed = ["bash", "curl", "eFa-next", "eFa-next-base", "git-core", "mariadb-server", "perl-Git", "perl-interpreter", "postfix",
                             "python3", "python3-flask", "redhat-rpm-config", "rpm-build", "rspamd"]
                runtime = ["python3", "mariadb-server", "postfix", "rspamd", "python3-flask", "perl-interpreter"]
                stubs = ('python3() { printf "%s\\n" ' + " ".join(runtime) + '; }\n'
                         'rpm() { case "$1" in -qa) printf "%s\\n" ' + " ".join(installed) + ';;'
                         f' -e) if [ "$2" = --test ]; then return {test_ok}; fi; echo "rpm -e ${{*:2}}";; -q) return 0;; esac; }}\n'
                         'dnf() { :; }\n')
                out = subprocess.run(["bash", "-c", f"export LC_ALL=C; LOG_DIR={log}; SOURCE_DIR=/x\n{stubs}{part}\nremove_build_tools"],
                                     capture_output=True, text=True, check=True).stdout
                removed = [line for line in out.splitlines() if line.startswith("rpm -e ")]
                if expect_removed:
                    self.assertEqual(removed, [expect_removed], out)
                else:
                    self.assertEqual(removed, [], out)
                    self.assertIn("build tools stay", out)

    def test_nginx_http2_follows_the_version(self):
        """nginx-config.sh: "http2 on;" from nginx 1.25.1 on, "listen ... http2" before (1.20 of AppStream refused the file)."""
        import shutil
        import subprocess
        import tempfile
        if not shutil.which("sh"):
            self.skipTest("no sh")
        with open(os.path.join(TOP, "next", "usr", "lib", "eFa", "setup", "nginx-config.sh"), encoding="utf-8") as fh:
            script = fh.read()
        switch = script[script.index('version="$(nginx -v'):script.index("# SELinux must allow")]
        for version, wanted in (("1.20.1", "listen 443 ssl http2 default_server;"), ("1.24.0", "listen 443 ssl http2 default_server;"),
                                ("1.25.1", "http2 on;"), ("1.26.3", "http2 on;")):
            with tempfile.TemporaryDirectory() as folder:
                conf = os.path.join(folder, "efa.conf").replace(os.sep, "/")
                with open(conf, "w") as fh:
                    fh.write("server {\n    listen 443 ssl default_server;\n    http2 on;\n    server_name \"\";\n}\n")
                fake = 'nginx() { echo "nginx version: nginx/%s" >&2; }\n' % version
                subprocess.run(["sh", "-c", fake + switch.replace("/etc/nginx/conf.d/efa.conf", conf)], check=True)
                with open(conf) as fh:
                    text = fh.read()
                self.assertIn(wanted, text, version)
                self.assertEqual(text.count("http2"), 1, version)

    def test_reinstall_after_a_failed_setup_is_a_first_install(self):
        """%pre: first install until /etc/eFa-Version of eFa-next 6 exists, also on a reinstall (its $1 is 2), unless the
        host is set up (CONFIGURED:YES): an update of a set-up host without the version file must not run the first-install
        steps, they would replace its settings."""
        import subprocess
        import tempfile
        for name, state in (("eFa.spec", "eFa"), ("eFa-base.spec", "eFa-base")):
            with open(os.path.join(TOP, "rpm", name), encoding="utf-8") as fh:
                pre = fh.read().split("%pre\n", 1)[1].split("%posttrans", 1)[0]
            self.assertNotIn('"$1" -eq 1', pre, name)
            decision = pre.split("mkdir -p /var/lib/rpm-state/%s\n" % state, 1)[1].split("exit 0", 1)[0]
            for version, config, first in (("", "", True), ("eFa-6.0.0.5\n", "", False), ("", "CONFIGURED:YES\n", False),
                                           ("", "CONFIGURED:NO\n", True), ("eFa-5.0.0\n", "", True)):
                with tempfile.TemporaryDirectory() as folder:
                    folder = folder.replace(os.sep, "/")
                    for file, text in (("version", version), ("config", config)):
                        if text:
                            with open(folder + "/" + file, "w") as fh:
                                fh.write(text)
                    script = (decision.replace("/etc/eFa-Version", folder + "/version").replace("/etc/eFa/eFa-Config", folder + "/config")
                              .replace("/var/lib/rpm-state/%s/first-install" % state, folder + "/first-install"))
                    subprocess.run(["sh", "-c", script], check=True)
                    self.assertEqual(os.path.exists(folder + "/first-install"), first, (name, version, config))

    def test_build_tools_checked_before_rpmbuild(self):
        """build-rpms.py names the missing BuildRequires and the builddep command instead of a traceback of rpmbuild."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("build_rpms", os.path.join(TOP, "build", "build-rpms.py"))
        build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build)
        specs = [os.path.join(TOP, "rpm", name) for name in ("eFa-base.spec", "eFa.spec")]
        self.assertIn("checkpolicy", build.build_requires(specs[0]))
        self.assertEqual(build.missing_build_requires(specs, lambda name: name != "checkpolicy"), ["checkpolicy"])
        self.assertEqual(build.missing_build_requires(specs, lambda name: True), [])

    def test_stray_program_bytecode_cleaned_up(self):
        """%posttrans of both packages removes bytecode of eFa-next programs next to /usr/sbin and /usr/local/sbin, nothing else."""
        import shutil
        import subprocess
        import tempfile
        if not shutil.which("sh"):
            self.skipTest("no sh")
        for spec_name in ("eFa.spec", "eFa-base.spec"):
            with open(os.path.join(TOP, "rpm", spec_name), encoding="utf-8") as fh:
                posttrans = fh.read().split("%posttrans", 1)[1].split("%preun", 1)[0]
            loop = re.search(r"^for cache in .*?^done$", posttrans, re.M | re.S).group(0)
            with tempfile.TemporaryDirectory() as root:
                sbin, local = os.path.join(root, "sbin", "__pycache__"), os.path.join(root, "local", "__pycache__")
                for folder, names in ((sbin, ("efactlcpython-39.pyc", "efa-tuicpython-39.pyc")), (local, ("efactl-runner.cpython-39.pyc", "other.cpython-39.pyc"))):
                    os.makedirs(folder)
                    for name in names:
                        open(os.path.join(folder, name), "w").close()
                script = loop.replace("/usr/sbin/__pycache__", sbin.replace(os.sep, "/")).replace("/usr/local/sbin/__pycache__", local.replace(os.sep, "/"))
                subprocess.run(["sh", "-c", script], check=True)
                self.assertFalse(os.path.exists(sbin), spec_name)
                self.assertEqual(os.listdir(local), ["other.cpython-39.pyc"], spec_name)

    def test_checked_hash_bytecode_follows_a_change_of_the_same_size_and_time(self):
        """The fault: same size, same clamped time, so the timestamp bytecode stays valid. With checked-hash the new code runs."""
        import subprocess
        import sys
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            module = os.path.join(folder, "efa_probe_mod.py")
            run = [sys.executable, "-c", "import efa_probe_mod; print(efa_probe_mod.X)"]
            with open(module, "w") as fh:
                fh.write("X = 1\n")
            os.utime(module, (1700000000, 1700000000))
            subprocess.run([sys.executable, "-m", "compileall", "-q", folder], check=True)
            with open(module, "w") as fh:
                fh.write("X = 2\n")
            os.utime(module, (1700000000, 1700000000))
            old = subprocess.run(run, cwd=folder, capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(old.stdout.strip(), "1", "the timestamp bytecode still wins: the fault this guards against")
            subprocess.run([sys.executable, "-m", "compileall", "-q", "-f", "--invalidation-mode", "checked-hash", folder], check=True)
            new = subprocess.run(run, cwd=folder, capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(new.stdout.strip(), "2")

    def test_mail_services_hardened(self):
        # A2: the services that parse untrusted mail carry the lockdown drop-in; the root orchestrators do not get it.
        units = os.path.join(TOP, "next/usr/lib/systemd/system")
        for name in ("efa-cdr", "efa-maillog", "efa-milter-health", "efa-outbound", "efa-sasl", "efa-portal"):
            path = os.path.join(units, name + ".service.d", "hardening.conf")
            self.assertTrue(os.path.exists(path), path)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for directive in ("CapabilityBoundingSet=", "SystemCallFilter=@system-service", "RestrictAddressFamilies=", "NoNewPrivileges=yes"):
                self.assertIn(directive, text, name)
        for name in ("efactl-runner", "efa-portal-helper", "efa-init", "efa-cluster", "efa-autoupdate"):
            self.assertFalse(os.path.exists(os.path.join(units, name + ".service.d", "hardening.conf")), name)

    def test_no_firewall_reload_anywhere(self):
        for path in self.files():
            if "tests" in path.split(os.sep):
                continue
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn("--reload", fh.read(), path)

    def test_logrotate_covers_all_files(self):
        with open(os.path.join(TOP, "src/eFa-base/root/etc/logrotate.d/eFa"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("/var/log/eFa/* {", text)
        self.assertIn("olddir /var/log/eFa-archive", text)
        for word in ("monthly", "rotate 4", "compress"):
            self.assertIn(word, text)


if __name__ == "__main__":
    unittest.main()

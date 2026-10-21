"""Behavioural tests for ghl_jail: every test launches the real CLI and checks what the jailed process can and cannot do.

Only fake canary files in a temporary directory are used. Run with:  python test_ghl_jail.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
JAIL = os.path.join(HERE, "ghl_jail.py")
BASE_PYTHON = os.path.join(sys.base_prefix, "python.exe")
CANARY = "FAKE-CANARY-NOT-A-SECRET"


def jail(mode, project, *command, net=None, keep_env=(), env=None, timeout=180):
    args = [sys.executable, JAIL, "run", "--quiet", "--mode", mode, "--project", project]
    if net:
        args += ["--net", net]
    for name in keep_env:
        args += ["--keep-env", name]
    args += ["--", *command]
    return subprocess.run(args, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout, env=env)


class Common:
    """Checks that must hold in both modes."""
    MODE = None

    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="ghl_jail_test_")
        cls.project = os.path.join(cls.base, "project")
        cls.secrets = os.path.join(cls.base, "secrets")
        cls.outside = os.path.join(cls.base, "outside")
        for d in (cls.project, cls.secrets, cls.outside):
            os.makedirs(d)
        cls.secret_file = os.path.join(cls.secrets, "aws_credentials")
        with open(cls.secret_file, "w") as fh:
            fh.write(f"aws_secret_access_key = {CANARY}\n")
        with open(os.path.join(cls.project, "main.txt"), "w") as fh:
            fh.write("hello\n")
        subprocess.run(["git", "init", "-q", cls.project], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def j(self, *command, **kw):
        return jail(self.MODE, self.project, *command, **kw)

    def test_control_the_host_can_read_the_canary(self):
        with open(self.secret_file) as fh:
            self.assertIn(CANARY, fh.read())

    def test_can_write_inside_the_project(self):
        r = self.j("cmd.exe", "/c", "echo inside> written_by_jail.txt")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.project, "written_by_jail.txt")))

    def test_cannot_read_a_secret_outside_the_project(self):
        r = self.j("cmd.exe", "/c", f'type "{self.secret_file}"')
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn(CANARY, r.stdout + r.stderr)
        self.assertIn("denied", (r.stdout + r.stderr).lower())

    def test_cmd_reads_a_file_inside_the_project(self):
        """Positive control for the cmd quoting used by the negative tests."""
        r = self.j("cmd.exe", "/c", f'type "{os.path.join(self.project, "main.txt")}"')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("hello", r.stdout)

    def test_cannot_write_outside_the_project(self):
        target = os.path.join(self.outside, "pwned.txt")
        r = self.j("cmd.exe", "/c", f'echo x> "{target}"')
        self.assertIn("denied", (r.stdout + r.stderr).lower())
        self.assertFalse(os.path.exists(target))

    def test_environment_secrets_do_not_reach_the_child(self):
        env = dict(os.environ, FAKE_SECRET_TOKEN="tok-abc123", AWS_SECRET_ACCESS_KEY="aws-xyz789")
        r = self.j("cmd.exe", "/c", "set", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        for leaked in ("tok-abc123", "aws-xyz789", "FAKE_SECRET_TOKEN", "AWS_SECRET_ACCESS_KEY"):
            self.assertNotIn(leaked, r.stdout)

    def test_keep_env_passes_a_named_variable(self):
        env = dict(os.environ, FAKE_SECRET_TOKEN="tok-abc123")
        r = self.j("cmd.exe", "/c", "set", keep_env=["FAKE_SECRET_TOKEN"], env=env)
        self.assertIn("tok-abc123", r.stdout)

    def test_python_runs_and_prints(self):
        r = self.j(BASE_PYTHON, "-c", "print(6*7)")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "42")

    def test_python_can_write_in_the_project_only(self):
        inside = os.path.join(self.project, "py_out.txt").replace("\\", "/")
        outside = os.path.join(self.outside, "py_out.txt").replace("\\", "/")
        code = f"open('{inside}','w').write('ok')\ntry:\n open('{outside}','w').write('no')\nexcept OSError:\n print('outside-denied')"
        r = self.j(BASE_PYTHON, "-c", code)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("outside-denied", r.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.project, "py_out.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.outside, "py_out.txt")))

    def test_java_runs(self):
        r = self.j("java", "-version")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_node_runs_a_script_in_the_project(self):
        """Needs NODE_OPTIONS=--preserve-symlinks(-main) from the launcher (container and token) and, in token mode, a
        default DACL that lets the child open itself (OpenSSL seeds through the legacy CryptoAPI)."""
        with open(os.path.join(self.project, "hello.js"), "w") as fh:
            fh.write("console.log('node-ok')")
        r = self.j("node", "hello.js")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("node-ok", r.stdout)

    def test_node_cannot_read_a_secret_outside(self):
        secret = self.secret_file.replace("\\", "/")
        with open(os.path.join(self.project, "leak.js"), "w") as fh:
            fh.write(f"try {{ console.log(require('fs').readFileSync('{secret}', 'utf8')) }} catch (e) {{ console.log('denied', e.code) }}")
        r = self.j("node", "leak.js")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(CANARY, r.stdout)
        self.assertIn("denied", r.stdout)



class ContainerMode(Common, unittest.TestCase):
    MODE = "container"

    def test_no_network_by_default(self):
        code = "import socket,sys\ntry:\n socket.create_connection(('1.1.1.1',443),timeout=3)\nexcept OSError as e:\n print('blocked',type(e).__name__); sys.exit(3)\nprint('connected')"
        r = self.j(BASE_PYTHON, "-c", code)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("blocked", r.stdout)

    def test_node_has_no_network_by_default(self):
        with open(os.path.join(self.project, "net.js"), "w") as fh:
            fh.write("require('net').connect(443,'1.1.1.1').on('connect',()=>{console.log('net-open');process.exit(0)})"
                     ".on('error',e=>{console.log('net-blocked',e.code);process.exit(3)})")
        r = self.j("node", "net.js")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("net-blocked", r.stdout)

    @unittest.expectedFailure
    def test_git_status_works(self):
        """Known limitation: this Windows build denies the NUL device to AppContainers and git opens it at startup."""
        r = self.j("git", "status", "--short")
        self.assertEqual(r.returncode, 0, r.stderr)


class AutoMode(Common, unittest.TestCase):
    """auto = container for everything except programs that need the NUL device (git), which go to token mode."""
    MODE = "auto"

    def test_git_status_works_and_the_switch_is_announced(self):
        r = self.j("git", "status", "--short")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("main.txt", r.stdout)
        self.assertIn("using token mode (network NOT restricted)", r.stderr)

    def test_other_programs_stay_in_container_without_network(self):
        code = "import socket,sys\ntry:\n socket.create_connection(('1.1.1.1',443),timeout=3)\nexcept OSError:\n print('blocked'); sys.exit(3)\nprint('connected')"
        r = self.j(BASE_PYTHON, "-c", code)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertNotIn("token mode", r.stderr)


class TokenMode(Common, unittest.TestCase):
    MODE = "token"

    def test_git_status_works(self):
        r = self.j("git", "status", "--short")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("main.txt", r.stdout)

    def test_git_cannot_read_a_secret_outside(self):
        r = self.j("git", "hash-object", self.secret_file)
        self.assertNotEqual(r.returncode, 0)
        self.assertRegex(r.stderr.lower(), "denied|permission|unable to open")

    def test_python_devnull_works(self):
        code = "import subprocess;subprocess.run(['cmd','/c','echo x'],stdout=subprocess.DEVNULL);print('devnull-ok')"
        r = self.j(BASE_PYTHON, "-c", code)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("devnull-ok", r.stdout)

    def test_npm_runs(self):
        """npm needs the network, so it belongs in token mode. (In container mode a toolchain inside the user profile is not
        reachable, because cmd.exe cannot traverse the profile folders to read npm.cmd.)"""
        subprocess.run([sys.executable, JAIL, "cleanup"], capture_output=True)
        r = self.j("npm", "--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout.strip(), r"^\d+\.\d+\.\d+$")

    def test_cannot_read_the_user_profile(self):
        canary = os.path.join(os.path.expanduser("~"), "ghl_jail_profile_canary.txt")
        with open(canary, "w") as fh:
            fh.write(CANARY)
        try:
            r = self.j("cmd.exe", "/c", f'type "{canary}"')
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn(CANARY, r.stdout + r.stderr)
            self.assertIn("denied", (r.stdout + r.stderr).lower())
        finally:
            os.remove(canary)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        subprocess.run([sys.executable, JAIL, "cleanup"], capture_output=True)

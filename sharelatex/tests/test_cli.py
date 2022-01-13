from contextlib import contextmanager
from git import Repo
import logging
import os
from subprocess import check_call
import tempfile
import unittest

from sharelatex import SyncClient, walk_project_data, get_authenticator_class

from ddt import ddt, data, unpack


logging.basicConfig(level=logging.DEBUG)


BASE_URL = os.environ.get("CI_BASE_URL")
USERNAMES = os.environ.get("CI_USERNAMES")
PASSWORDS = os.environ.get("CI_PASSWORDS")
AUTH_TYPE = os.environ.get("CI_AUTH_TYPE")

# Operate with a list of users
# This workarounds the rate limitation on the API if enough usernames and passwords are given
# Each test will pick the next (username, password) in the queue and put it back at the end
# An alternative would be to define a smoke user in the settings
# settings.smokeTest = True, settings.smokeTest.UserId
import queue

CREDS = queue.Queue()
for username, passwords in zip(USERNAMES.split(","), PASSWORDS.split(",")):
    CREDS.put((username, passwords))


def log(f):
    def wrapped(*args, **kwargs):
        print("-" * 60)
        print("{:^60}".format(f.__name__.upper()))
        print("-" * 60)
        return f(*args, **kwargs)

    return wrapped


class Project:
    def __init__(self, client, project_id, fs_path, repo=None):
        self.client = client
        self.project_id = project_id
        self.fs_path = fs_path
        self.repo = repo
        self.url = f"{BASE_URL}/project/{project_id}"

    def get_doc_by_path(self, path):
        """Doc only."""

        def predicate(entity):
            return entity["folder_path"] == os.path.dirname(path) and entity[
                "name"
            ] == os.path.basename(path)

        project_data = self.client.get_project_data(self.project_id)
        files = walk_project_data(project_data, predicate=predicate)
        myfile = next(files)
        content = self.client.get_doc(self.project_id, myfile["_id"])
        return content

    def delete_file_by_path(self, path):
        """File only."""

        def predicate(entity):
            return entity["folder_path"] == os.path.dirname(path) and entity[
                "name"
            ] == os.path.basename(path)

        project_data = self.client.get_project_data(self.project_id)
        files = walk_project_data(project_data, predicate=predicate)
        myfile = next(files)
        self.client.delete_file(self.project_id, myfile["_id"])


@contextmanager
def project(project_name, branch=None):
    """A convenient contextmanager to create a temporary project on sharelatex."""

    # First we create a client.
    # For testing purpose we disable SSL verification everywhere
    username, password = CREDS.get()
    authenticator = get_authenticator_class(AUTH_TYPE)(
        BASE_URL, username, password, verify=False
    )
    client = SyncClient(base_url=BASE_URL, authenticator=authenticator, verify=False)
    with tempfile.TemporaryDirectory() as temp_path:
        os.chdir(temp_path)
        r = client.new(project_name)
        try:
            project_id = r["project_id"]
            fs_path = os.path.join(temp_path, project_id)
            project = Project(client, project_id, fs_path)

            # let's clone it
            args = f"--auth_type={AUTH_TYPE} --username={username} --password={password} --save-password --no-https-cert-check"
            check_call(f"git slatex clone {project.url} {args}", shell=True)
            os.chdir(project.fs_path)
            check_call("git config --local user.email 'test@test.com'", shell=True)
            check_call("git config --local user.name 'me'", shell=True)
            if branch is not None:
                check_call(f"git checkout -b {branch}", shell=True)
            project.repo = Repo()
            yield project
        except Exception as e:
            raise e
        finally:
            CREDS.put((username, password))
            client.delete(project_id, forever=True)


def new_project(branch=None):
    def _new_project(f):
        """A convenient decorator to launch a function in the
        context of a new project."""

        def wrapped(*args, **kwargs):
            with project(f.__name__, branch=branch) as p:
                kwargs.update(project=p)
                return f(*args, **kwargs)

        return wrapped

    return _new_project


@ddt
class TestCli(unittest.TestCase):
    @new_project()
    def test_clone(self, project=None):
        pass

    @new_project()
    def test_clone_and_pull(self, project=None):
        check_call("git slatex pull", shell=True)

    @data("--force", "")
    @new_project()
    def test_clone_and_push(self, force, project=None):
        check_call(f"git slatex push {force}", shell=True)

    @data("test_branch", None)
    def test_clone_and_push_local_modification(self, branch):
        @new_project(branch=branch)
        def _test_clone_and_push_local_modification(project=None):
            """Local modification on main.tex"""
            check_call("echo test > main.tex", shell=True)
            project.repo.git.add(".")
            project.repo.index.commit("test")

            check_call("git slatex push", shell=True)
            remote_content = project.get_doc_by_path("/main.tex")

            # for some reason there's a trailing \n...
            self.assertEqual("test\n", remote_content)

        # run it
        _test_clone_and_push_local_modification()

    @data(
        ["--force", None], ["--force", "test_branch"], ["", None], ["", "test_branch"]
    )
    @unpack
    def test_clone_and_push_local_addition(self, force, branch):
        @new_project(branch=branch)
        def _test_clone_and_push_local_addition(project=None):
            """Addition of a local file"""
            check_call("echo test > main2.tex", shell=True)
            project.repo.git.add(".")
            project.repo.index.commit("test")
            check_call(f"git slatex push {force}", shell=True)
            remote_content = project.get_doc_by_path("/main2.tex")

            # for some reason there's a trailing \n...
            self.assertEqual("test\n", remote_content)

        _test_clone_and_push_local_addition()

    @data("test_branch", None)
    def test_clone_and_pull_remote_addition(self, branch):
        @new_project(branch=branch)
        def _test_clone_and_pull_remote_addition(project=None):
            """Addition of a remote file."""
            check_call("mkdir -p test", shell=True)
            check_call("echo test > test/test.tex", shell=True)

            # create the file on the remote copy
            client = project.client
            project_id = project.project_id
            project_data = client.get_project_data(project_id)
            folder_id = client.check_or_create_folder(project_data, "/test")
            client.upload_file(project_id, folder_id, "test/test.tex")

            # remove local file
            check_call("rm -rf test", shell=True)
            self.assertFalse(os.path.exists("test/test.tex"))

            # pull
            check_call("git slatex pull", shell=True)

            # check the file
            self.assertTrue(os.path.exists("test/test.tex"))
            # check content (there's an extra \n...)
            self.assertEqual("test\n", open("test/test.tex", "r").read())

        _test_clone_and_pull_remote_addition()

    @data(
        ["--force", None], ["--force", "test_branch"], ["", None], ["", "test_branch"]
    )
    @unpack
    def test_clone_and_push_local_deletion(self, force, branch):
        @new_project(branch=branch)
        def _test_clone_and_push_local_deletion(project=None):
            """Deletion of a local file"""
            check_call("rm main.tex", shell=True)
            project.repo.git.add(".")
            project.repo.index.commit("test")
            check_call(f"git slatex push {force}", shell=True)
            with self.assertRaises(StopIteration) as _:
                project.get_doc_by_path("/main.tex")

        _test_clone_and_push_local_deletion()

    @data(
        ["--force", None], ["--force", "test_branch"], ["", None], ["", "test_branch"]
    )
    @unpack
    def test_clone_and_pull_remote_deletion(self, force, branch):
        @new_project(branch=branch)
        def _test_clone_and_pull_remote_deletion(project=None):
            """Deletion of remote universe.png"""
            project.delete_file_by_path("/universe.jpg")
            check_call("git slatex pull", shell=True)
            # TODO: we could check the diff
            self.assertFalse(os.path.exists("universe.jpg"))

        _test_clone_and_pull_remote_deletion()

    def test_clone_malformed_project_URL(self):
        """try clone with malformed project URL"""
        with self.assertRaises(Exception) as _:
            check_call("git slatex clone not_a_PROJET_URL -vvv", shell=True)

    @new_project()
    def test_new(self, project):
        check_call(f"git slatex new test_new {BASE_URL}", shell=True)


class TestLib(unittest.TestCase):
    @new_project()
    def test_copy(self, project=None):
        client = project.client
        response = client.clone(project.project_id, "cloned_project")
        client.delete(response["project_id"], forever=True)

    @new_project()
    def test_update_project_settings(self, project=None):
        client = project.client
        response = client.update_project_settings(project.project_id, name="RENAMED")
        project_data = client.get_project_data(project.project_id)
        self.assertEqual("RENAMED", project_data["name"])


if __name__ == "__main__":
    unittest.main(verbosity=3)

import logging
import os
from pathlib import Path

import getpass

from sharelatex import (
    get_authenticator_class,
    SyncClient,
    walk_project_data,
    set_logger,
)

import click
from git import Repo
from git.config import cp
from zipfile import ZipFile
import keyring

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

set_logger(logger)


def remote_headless():
    """Exit if we do not have access to the keyring"""
    print("Keyring is not available - on remote or headless machines try:")
    print("source $HOME/.dbus/session-bus/*")
    os._exit(os.EX_UNAVAILABLE)


def set_log_level(verbose=0):
    """set log level from interger value"""
    LOG_LEVELS = (logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG)
    logger.setLevel(LOG_LEVELS[verbose])


SLATEX_SECTION = "slatex"
SYNC_BRANCH = "__remote__sharelatex__"
PROMPT_BASE_URL = "Base url: "
PROMPT_PROJECT_ID = "Project id: "
PROMPT_AUTH_TYPE = "Authentification type (default|irisa): "
PROMPT_USERNAME = "Username: "
PROMPT_PASSWORD = "Password: "
PROMPT_CONFIRM = "Do you want to save your password in your OS keyring system (y/n) ?"
MAX_NUMBER_ATTEMPTS = 3


class Config:
    """Handle gitconfig read/write operations in a transparent way."""

    def __init__(self, repo):
        self.repo = repo
        try:
            self.keyring = keyring.get_keyring()
        except:
            remote_headless()

    def get_password(self, service, username):
        try:
            return self.keyring.get_password(service, username)
        except: 
            remote_headless()

    def set_password(self, service, username, password):
        try:
            self.keyring.set_password(service, username, password)
        except: 
            remote_headless()

    def delete_password(self, service, username):
        try: 
            self.keyring.delete_password(service, username)
        except: 
            remote_headless()

    def set_value(self, section, key, value, config_level="repository"):
        """Set a config value in a specific section.

        Note:
            If the section doesn't exist it is created.

        Args:
            section (str): the section name
            key (str): the key to set
            value (str): the value to set
        """
        with self.repo.config_writer(config_level) as c:
            try:
                c.set_value(section, key, value)
            except cp.NoSectionError as e:
                # No section is found, we create a new one
                logger.debug(e)
                c.set_value(section, "init", "")
            except Exception as e:
                raise e
            finally:
                c.release()

    def get_value(self, section, key, default=None, config_level=None):
        """Get a config value in a specific section of the config.

                Note: this returns the associated value if found.
                      Otherwise it returns the default value.

                Args:
                    section (str): the section name: str
                    key (str): the key to set
                    default (str): the defaut value to apply
                    config_level (str): the config level to look for
                    see:
        https://gitpython.readthedocs.io/en/stable/reference.html#git.repo.base.Repo.config_level

        """
        with self.repo.config_reader(config_level) as c:
            try:
                value = c.get_value(section, key)
            except cp.NoSectionError as e:
                logger.debug(e)
                value = default
            except cp.NoOptionError as e:
                logger.debug(e)
                value = default
            except Exception as e:
                raise e
            finally:
                return value


def get_clean_repo(path=None):
    """Create the git.repo object from a directory.

    Note:

        This initialize the git repository and fails if the repo isn't clean.
        This is run prior to many operations to make sure there isn't any
        untracked/uncomitted files in the repo.

    Args:
        path (str): the path of the repository in the local file system.

    Returns:
        a git.Repo data-structure.

    Raises:
        Exception if the repo isn't clean
    """
    repo = Repo.init(path=path)
    # Fail if the repo is clean
    if repo.is_dirty(index=True, working_tree=True, untracked_files=True):
        #logger.error(repo.git.status())
        logger.warning("The repo isn't clean. Commit your changes.")
        os._exit(-1)
    return repo


def refresh_project_information(
    repo, base_url=None, project_id=None, https_cert_check=None
):
    """Get and/or set the project information in/from the git config.

    If the information is set in the config it is retrieved, otherwise it is set.

    Args:
        repo (git.Repo): The repo object to read the config from
        base_url (str): the base_url to consider
        project_id (str): the project_id to consider

    Returns:
        tuple (base_url, project_id) after the refresh occurs.
    """
    config = Config(repo)
    if base_url is None:
        u = config.get_value(SLATEX_SECTION, "baseUrl")
        if u is not None:
            base_url = u
        else:
            base_url = input(PROMPT_BASE_URL)
            config.set_value(SLATEX_SECTION, "baseUrl", base_url)
    else:
        config.set_value(SLATEX_SECTION, "baseUrl", base_url)
    if project_id is None:
        p = config.get_value(SLATEX_SECTION, "projectId")
        if p is not None:
            project_id = p
        else:
            project_id = input(PROMPT_PROJECT_ID)
        config.set_value(SLATEX_SECTION, "projectId", project_id)
    else:
        config.set_value(SLATEX_SECTION, "projectId", project_id)
    if https_cert_check is None:
        c = config.get_value(SLATEX_SECTION, "httpsCertCheck")
        if c is not None:
            https_cert_check = c
        else:
            https_cert_check = True
            config.set_value(SLATEX_SECTION, "httpsCertCheck", https_cert_check)
    else:
        config.set_value(SLATEX_SECTION, "httpsCertCheck", https_cert_check)

    return base_url, project_id, https_cert_check


def refresh_account_information(
    repo,
    auth_type,
    username=None,
    password=None,
    save_password=None,
    ignore_saved_user_info=False,
):
    """Get and/or set the account information in/from the git config.

    If the information is set in the config it is retrieved, otherwise it is set.
    Note that no further encryption of the password is offered here.

    Args:
        repo (git.Repo): The repo object to read the config from
        username (str): The username to consider
        password (str): The password to consider
        save_password (boolean): True for save user account information (in OS
                                 keyring system) if needed
        ignore_saved_user (boolean): True for ignore user account information (in
                                 OS keyring system) if present
    Returns:
        tuple (login_path, username, password) after the refresh occurs.
    """

    config = Config(repo)
    base_url = config.get_value(SLATEX_SECTION, "baseUrl")

    if auth_type is None:
        if not ignore_saved_user_info:
            u = config.get_value(SLATEX_SECTION, "authType")
            if u:
                auth_type = u
    if auth_type is None:
        auth_type = input(PROMPT_AUTH_TYPE)
    config.set_value(SLATEX_SECTION, "authType", auth_type)

    if username is None:
        if not ignore_saved_user_info:
            u = config.get_value(SLATEX_SECTION, "username")
            if u:
                username = u
    if username is None:
        username = input(PROMPT_USERNAME)
    config.set_value(SLATEX_SECTION, "username", username)

    if password is None:
        if not ignore_saved_user_info:
            p = config.get_password(base_url, username)
            if p:
                password = p
    if password is None:
        password = getpass.getpass(PROMPT_PASSWORD)
        if save_password is None:
            r = input(PROMPT_CONFIRM)
            if r == "Y" or r == "y":
                save_password = True
    if save_password:
        config.set_password(base_url, username, password)
    return auth_type, username, password


def getClient(
    repo,
    base_url,
    auth_type,
    username,
    password,
    verify,
    save_password=None,
):
    logger.info(f"try to open session on {base_url} with {username}")
    client = None

    authenticator = get_authenticator_class(auth_type)(
        base_url, username, password, verify
    )
    for i in range(MAX_NUMBER_ATTEMPTS):
        try:
            client = SyncClient(
                base_url=base_url,
                authenticator=authenticator,
                verify=verify,
            )
            break
        except Exception as inst:
            client = None
            logger.warning("{}  : attempt # {} ".format(inst, i + 1))
            auth_type, username, password = refresh_account_information(
                repo,
                auth_type,
                save_password=save_password,
                ignore_saved_user_info=True,
            )
    if client is None:
        raise Exception("maximum number of authentication attempts is reached")
    return client


def update_ref(repo, message="update_ref"):
    """Makes the remote pointer to point on the latest revision we have.

    This is called after a successfull clone, push, new. In short when we
    are sure the remote and the local are in sync.
    """
    git = repo.git

    git.add(".")
    # with this we can have two consecutive commit with the same content
    repo.index.commit(f"{message}")
    sync_branch = repo.create_head(SYNC_BRANCH, force=True)
    sync_branch.commit = "HEAD"


@click.group()
def cli():
    pass


def log_options(function):
    function = click.option(
        "-v",
        "--verbose",
        count=True,
        default=2,
        help="verbose level (can be: -v, -vv, -vvv)",
    )(function)
    function = click.option("-s", "--silent", "verbose", flag_value=0)(function)
    function = click.option("--debug", "-d", "verbose", flag_value=3)(function)
    return function


def authentication_options(function):
    function = click.option(
        "--auth_type",
        "-a",
        default="default",
        help="""Authentification type (default|irisa).""",
    )(function)

    function = click.option(
        "--username",
        "-u",
        default=None,
        help="""Username for sharelatex server account, if username is not provided, it will be
 asked online""",
    )(function)
    function = click.option(
        "--password",
        "-p",
        default=None,
        help="""User password for sharelatex server, if password is not provided, it will
 be asked online""",
    )(function)
    function = click.option(
        "--save-password/--no-save-password",
        default=None,
        help="""Save user account information (in OS keyring system)""",
    )(function)
    function = click.option(
        "--ignore-saved-user-info",
        default=False,
        help="""Forget user account information already saved (in OS keyring system)""",
    )(function)

    return function


@cli.command(help="test log levels")
@log_options
def test(verbose):
    set_log_level(verbose)
    logger.debug("debug")
    logger.info("info")
    logger.error("error")
    logger.warning("warning")
    print("print")


def _pull(repo, client, project_id):
    if repo.is_dirty(index=True, working_tree=True, untracked_files=True):
        logger.error(repo.git.status())
        print("The repository isn't clean: please add and commit or stash your files")
        return

    # attempt to "merge" the remote and the local working copy

    git = repo.git
    active_branch = repo.active_branch.name
    git.checkout(SYNC_BRANCH)

    # delete all files but not .git !!!!
    files = list(Path(repo.working_tree_dir).rglob("*"))
    files.reverse()
    for p in files:
        if not str(p.relative_to(Path(repo.working_tree_dir))).startswith(".git"):
            if p.is_dir():
                p.rmdir()
            else:
                Path.unlink(p)

    # TODO: try to check directly from server what file or directory
    # is changed/delete/modify instead to reload whole project zip
    client.download_project(project_id)
    update_ref(repo, message="pre pull")
    git.checkout(active_branch)
    git.merge(SYNC_BRANCH)


@cli.command(help="Compile the remote version of a project")
@click.argument("project_id", default="")
@authentication_options
@log_options
def compile(
    project_id,
    auth_type,
    username,
    password,
    save_password,
    ignore_saved_user_info,
    verbose,
):
    set_log_level(verbose)
    repo = Repo()
    base_url, project_id, https_cert_check = refresh_project_information(repo)
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )
    client = getClient(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )

    response = client.compile(project_id)
    logger.debug(response)


@cli.command(help="Send a invitation to share (edit/view) a project")
@click.argument("email", default="")
@click.option("--project_id", default=None)
@click.option(
    "--can-edit/--read-only",
    default=True,
    help="""Authorize user to edit the project or not""",
)
@authentication_options
@log_options
def share(
    project_id,
    email,
    can_edit,
    auth_type,
    username,
    password,
    save_password,
    ignore_saved_user_info,
    verbose,
):
    set_log_level(verbose)
    repo = Repo()
    base_url, project_id, https_cert_check = refresh_project_information(
        repo, project_id=project_id
    )
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )
    client = getClient(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )

    response = client.share(project_id, email, can_edit)
    logger.debug(response)


@cli.command(
    help=f"""Pull the files from sharelatex.

    In the current repository, it works as follows:

    1. Pull in ``{SYNC_BRANCH}`` branch the latest version of the remote project\n
    2. Attempt a merge in the working branch. If the merge can't be done automatically,
       you will be required to fix the conflict manually
    """
)
@authentication_options
@log_options
def pull(
    auth_type,
    username,
    password,
    save_password,
    ignore_saved_user_info,
    verbose,
):
    set_log_level(verbose)
    repo = Repo()
    base_url, project_id, https_cert_check = refresh_project_information(repo)
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )
    client = getClient(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )
    # Fail if the repo is clean
    _pull(repo, client, project_id)


@cli.command(
    help=f"""
Get (clone) the files from sharelatex projet URL and create a local git depot.

The optional target directory will be created if it doesn't exist. The command
fails if it already exists. Connection information can be saved in the local git
config.

It works as follow:

    1. Download and unzip the remote project in the target directory\n
    2. Initialize a fresh git repository\n
    3. Create an extra ``{SYNC_BRANCH}`` to keep track of the remote versions of
       the project. This branch must not be updated manually.
"""
)
@click.argument(
    "projet_url", default=""
)  # , help="The project url (https://sharelatex.irisa.fr/1234567890)")
@click.argument("directory", default="")  # , help="The target directory")
@click.option(
    "--https-cert-check/--no-https-cert-check",
    default=True,
    help="""force to check https certificate or not""",
)
@authentication_options
@log_options
def clone(
    projet_url,
    directory,
    auth_type,
    username,
    password,
    save_password,
    ignore_saved_user_info,
    https_cert_check,
    verbose,
):
    set_log_level(verbose)
    # TODO : robust parse regexp
    slashparts = projet_url.split("/")
    project_id = slashparts[-1]
    base_url = "/".join(slashparts[:-2])
    if base_url == "":
        raise Exception("projet_url is not well formed or missing")
    if directory == "":
        directory = Path(os.getcwd())
        directory = Path(directory, project_id)
    else:
        directory = Path(directory)
    if os.path.isdir(directory):
        print("Exiting: Local Directory Exists")
        os._exit(os.EX_CANTCREAT)
    directory.mkdir(parents=True, exist_ok=False)

    repo = get_clean_repo(path=directory)

    base_url, project_id, https_cert_check = refresh_project_information(
        repo, base_url, project_id, https_cert_check
    )
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )

    try:
        client = getClient(
            repo,
            base_url,
            auth_type,
            username,
            password,
            https_cert_check,
            save_password,
        )
    except Exception as inst:
        import shutil

        shutil.rmtree(directory)
        raise inst
    client.download_project(project_id, path=directory)
    # TODO(msimonin): add a decent default .gitignore ?
    update_ref(repo, message="clone")


@cli.command(
    help="""Synchronize the local copy with the remote version.

This works as follow:

1. The remote version is pulled (see the :program:`pull` command)\n
2. After the merge succeed, the merged version is uploaded back to the remote server.\n
   Note that only the files that have changed (modified/added/removed) will be uploaded.
"""
)
@click.option("--force", is_flag=True, help="Force push")
@authentication_options
@log_options
def push(
    force,
    auth_type,
    username,
    password,
    save_password,
    ignore_saved_user_info,
    verbose,
):
    set_log_level(verbose)

    def _upload(client, project_data, path):
        # initial factorisation effort
        logger.debug(f"Uploading {path}")
        project_id = project_data["_id"]
        dirname = os.path.dirname(path)
        # TODO: that smells
        dirname = "/" + dirname
        # TODO encapsulate both ?
        folder_id = client.check_or_create_folder(project_data, dirname)
        p = f"{repo.working_dir}/{path}"
        client.upload_file(project_id, folder_id, p)

    def _delete(client, project_data, path):
        # initial factorisation effort
        logger.debug(f"Deleting {path}")
        project_id = project_data["_id"]
        dirname = os.path.dirname(path)
        # TODO: that smells
        dirname = "/" + dirname
        basename = os.path.basename(path)
        entities = walk_project_data(
            project_data,
            lambda x: x["folder_path"] == dirname and x["name"] == basename,
        )
        # there should be one
        entity = next(entities)
        if entity["type"] == "doc":
            client.delete_document(project_id, entity["_id"])
        elif entity["type"] == "file":
            client.delete_file(project_id, entity["_id"])

    repo = get_clean_repo()
    base_url, project_id, https_cert_check = refresh_project_information(repo)
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )

    client = getClient(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )

    if not force:
        _pull(repo, client, project_id)

    master_commit = repo.commit("HEAD")
    sync_commit = repo.commit(SYNC_BRANCH)
    diff_index = sync_commit.diff(master_commit)

    project_data = client.get_project_data(project_id)

    logger.debug("Modify files to upload :")
    for d in diff_index.iter_change_type("M"):
        _upload(client, project_data, d.a_path)

    logger.debug("new files to upload :")
    for d in diff_index.iter_change_type("A"):
        _upload(client, project_data, d.a_path)

    logger.debug("delete files :")
    for d in diff_index.iter_change_type("D"):
        _delete(client, project_data, d.a_path)

    logger.debug("rename files :")
    for d in diff_index.iter_change_type("R"):
        # git mv a b
        # for us this corresponds to
        # 1) deleting the old one (a)
        # 2) creating the new one (b)
        _delete(client, project_data, d.a_path)
        _upload(client, project_data, d.b_path)
    logger.debug("Path type changes :")
    for d in diff_index.iter_change_type("T"):
        # This one is maybe
        # 1) deleting the old one (a)
        # 2) creating the new one (b)
        _delete(client, project_data, d.a_path)
        _upload(client, project_data, d.b_path)

    update_ref(repo, message="push")


@cli.command(
    help="""
Upload the current directory as a new sharelatex project.

This litteraly creates a new remote project in sync with the local version.
"""
)
@click.argument("projectname")
@click.argument("base_url")
@click.option(
    "--https-cert-check/--no-https-cert-check",
    default=True,
    help="""force to check https certificate or not""",
)
@authentication_options
@log_options
def new(
    projectname,
    base_url,
    https_cert_check,
    auth_type,
    username,
    password,
    save_password,
    ignore_saved_user_info,
    verbose,
):
    set_log_level(verbose)
    repo = get_clean_repo()

    refresh_project_information(repo, base_url, "NOT SET", https_cert_check)
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )
    client = getClient(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )

    iter_file = repo.tree().traverse()
    archive_name = "%s.zip" % projectname
    archive_path = Path(archive_name)
    with ZipFile(str(archive_path), "w") as z:
        for f in iter_file:
            logger.debug(f"Adding {f.path} to the archive")
            z.write(f.path)

    response = client.upload(archive_name)
    logger.info("Successfully uploaded %s [%s]" % (projectname, response["project_id"]))
    archive_path.unlink()

    refresh_project_information(
        repo, base_url, response["project_id"], https_cert_check
    )
    update_ref(repo, message="upload")

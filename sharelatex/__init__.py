from json.decoder import JSONDecodeError
import logging
from typing import Dict, Tuple

# try to find CAS form
from lxml import html
import os
from pathlib import Path
import requests
import threading
import urllib.parse
import uuid
import zipfile

import filetype
from socketIO_client import SocketIO, BaseNamespace


from .__version__ import __version__


logger = logging.getLogger(__name__)


def set_logger(new_logger):
    global logger
    logger = new_logger


BASE_URL = "https://sharelatex.irisa.fr"
USER_AGENT = f"python-sharelatex {__version__}"


class SharelatexError(Exception):
    """Base class for the errors here."""

    pass


class CompilationError(SharelatexError):
    def __init__(self, json_status):
        super().__init__("Compilation failed", json_status)


def walk_project_data(project_data, predicate=lambda x: True):
    """Iterate on the project entities (folders, files).

    Args:
        project_data (dict): The project data as retrieved by
            :py:meth:`sharelatex.SyncClient.get_project_data`
        predicate (lambda): Lambda to filter the entry
            an entry is a dictionnary as in
            {"folder_id": <id of the current folder>,
             "folder_path": <complete path of the folder /a/folder/>,
             "name": <name of the entity>,
             "type": <type of the entity directory or file>,
             "_id" : <id of the entity>

    Returns:
        A generator for the matching entities
    """

    def _walk_project_data(current, parent):
        """Iterate on the project structure

        Args:
            current (dict): Current folder representation
            parent (str): Path of the parent folder
        """
        for c in current:
            if c["name"] == "rootFolder":
                folder_name = ""
            else:
                folder_name = c["name"]
            folder_path = os.path.join(parent, folder_name)
            folder_id = c["_id"]
            fd = {
                "folder_id": folder_id,
                "folder_path": folder_path,
                "name": folder_name,
                "type": "folder",
            }
            if predicate(fd):
                yield fd
            for f in c["fileRefs"]:
                fd = {
                    "folder_id": folder_id,
                    "folder_path": folder_path,
                    "name": folder_name,
                    "type": "file",
                }
                fd.update(f)
                if predicate(fd):
                    yield fd
            for d in c["docs"]:
                fd = {
                    "folder_id": folder_id,
                    "folder_path": folder_path,
                    "name": folder_name,
                    "type": "doc",
                }
                fd.update(d)
                if predicate(fd):
                    yield fd
            if len(c["folders"]) > 0:
                yield from _walk_project_data(c["folders"], folder_path)

    return _walk_project_data(project_data["rootFolder"], "/")


def lookup_folder(project_data, folder_path):
    """Lookup a folder by its path

    Args:
        project_data (dict): The project data as retrieved by
            :py:meth:`sharelatex.SyncClient.get_project_data`
        folder_path (str): The path of the folder. Must start with ``/``

    Returns:
        The folder id (str)

    Raises:
         StopIteration if the folder isn't found
    """
    folders = walk_project_data(
        project_data, predicate=lambda x: x["folder_path"] == folder_path
    )
    return next(folders)


def walk_files(project_data):
    """Iterates on the file only of a project.

    Args:
        project_data (dict): The project data as retrieved by
            :py:meth:`sharelatex.SyncClient.get_project_data`

    Raises:
        StopIteration if the file isn't found
    """
    return walk_project_data(project_data, lambda x: x["type"] == "file")


def check_login_error(response):
    """Check if there's an error in the request response

    The response text is
    - HTML if the auth is successful
    - json: otherwise
        {
            "message":
            {
                "text": "Your email or password is incorrect. Please try again",
                "type": "error"
            }
        }

    Args:
        response (request response): message returned by the sharelatex server

    Raise:
        Exception with the corresponding text in the message
    """
    try:
        json = response.json()
        message = json.get("message")
        if message is None:
            return
        t = message.get("type")
        if t is not None and t == "error":
            raise Exception(message.get("text", "Unknown error"))
    except JSONDecodeError:
        # this migh be a successful login here
        logger.info("Loggin successful")
        pass


def get_csrf_Token(html_text):
    """Retrieve csrf token from a html text page from sharelatex server.

    Args:
        html_text (str): The text from a html page of sharelatex server
    Returns:
        the csrf token (str) if found in html_text or None if not
    """
    #if "csrfToken" in html_text:
    #    ## works with Sharelatex <2.3
    #    #return re.search('(?<=csrfToken = ").{36}', html_text).group(0)
    #    ## works with Sharelatex 2.6.1
    #    #return re.search('(?<=csrfToken" content=").{36}', html_text).group(0)
    #    ## works with Sharelatex 2.X
    #    return re.findall(r'<input name="_csrf" type="hidden" value="(?P<token>.*?)">', html_text)[0] 
    #else:
    #    return None


    parsed = html.fromstring(html_text)
    meta = parsed.xpath("//meta[@name='ol-csrfToken']")
    #print(meta[0].get("content"))
    if not meta:
        return None
    else:
        return meta[0].get("content")


class Authenticator(object):
    def __init__(self):
        self.session: requests.session = None

    def authenticate(self) -> Tuple[str, Dict]:
        """Authenticate.

        Returns:
            Tuple of login data and the cookie (containing the session id)
            These two informations can be use to forge further requests
        """
        return None


class DefaultAuthenticator(Authenticator):
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool = True,
        login_path="/login",
        sid_name="sharelatex.sid",
    ):
        """Use the default login form of the community edition.

        Args:
            login_url: full url where the login form can be found
            username: username to use (an email address)
            password: the password to use
            verify: True to enable SSL verification (use False for self-signed
                testing instance)
        """
        super().__init__()
        self.login_url = urllib.parse.urljoin(base_url, login_path)
        self.username = username
        self.password = password
        self.verify = verify
        self.sid_name = sid_name

    def authenticate(self) -> Tuple[str, str]:
        r = self.session.get(self.login_url, verify=self.verify)
        self.csrf = get_csrf_Token(r.text)
        self.login_data = dict(
            email=self.username,
            password=self.password,
            _csrf=self.csrf,
        )
        logger.debug("try login")
        _r = self.session.post(self.login_url, data=self.login_data, verify=self.verify)
        _r.raise_for_status()
        # Check login error is for me not working in this way - i get json errors
        # check_login_error(_r) 
        # I just check if i have an csfr token - if yes then the login worked.
        # + faster; - not forwarding the message from the response.
        csfr_token=get_csrf_Token(_r.text)
        if csfr_token :
          login_data = dict(email=self.username, _csrf=get_csrf_Token(_r.text))
        else : 
          logger.warning("Could not login. Check username and password")
          os._exit(-1)
        return login_data, {self.sid_name: _r.cookies[self.sid_name]}


class IrisaAuthenticator(DefaultAuthenticator):
    """We use Gitlab as authentification backend (using OAUTH2).

    In this context, the login page redirect to the login page of gitlab(irisa),
    which in turn redirect to overleaf.  upon success we get back the project
    page where the csrf token can be found
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool = True,
        login_path="/auth/callback/gitlab",
    ):
        super().__init__(
            base_url, username, password, verify=verify, login_path=login_path
        )

    def authenticate(self) -> Tuple[str, str]:
        # go to the login form
        r = self.session.get(self.login_url, verify=self.verify)
        gitlab_form = html.fromstring(r.text)
        if len(gitlab_form.forms) > 0:
            # =1 for CAS, =2 for gitlab with LDAP (LDAP is 0 => force this choice)
            fo = gitlab_form.forms[0]
            # execution for CAS
            # authenticity_token for gitlab
            if any(
                field in fo.fields.keys()
                for field in ["execution", "authenticity_token"]
            ):
                self.login_data = {name: value for name, value in fo.form_values()}
                self.login_data["password"] = self.password
                self.login_data["username"] = self.username

                post_url = urllib.parse.urljoin(r.url, fo.action)
                _r = self.session.post(
                    post_url, data=self.login_data, verify=self.verify
                )
                _r.raise_for_status()
                # beware that here we're redirected to a redirect page
                # (not on sharelatex directly...)
                # This look like this
                # <h3 class="page-title">Redirecting</h3>
                #   <div>
                #       <a href="redirect_url"> Click here to redirect to
                #       [..]
                #
                # In this case, let's simply "click" on the link
                redirect_html = html.fromstring(_r.text)
                redirect_url = redirect_html.xpath("//a")[0].get("href")
                _r = self.session.get(redirect_url, verify=self.verify)
                _r.raise_for_status()
                check_login_error(_r)
                login_data = dict(email=self.username, _csrf=get_csrf_Token(_r.text))
                return login_data, {self.sid_name: _r.cookies[self.sid_name]}


def get_authenticator_class(auth_type: str):
    if auth_type == "default":
        return DefaultAuthenticator
    elif auth_type == "irisa":
        return IrisaAuthenticator
    else:
        raise ValueError(f"auth_type must be in (default|irisa) found {auth_type}")


class SyncClient:
    def __init__(
        self,
        *,
        base_url=BASE_URL,
        username: str = None,
        password: str = None,
        verify: bool = True,
        authenticator: Authenticator = None,
    ):
        """Creates the client.

        This mimics the browser behaviour when logging in.


        Args:
            base_url (str): Base url of the sharelatex server
            username (str): Username of the user (the email)
            password (str): Password of the user
            verify (bool): True iff SSL certificates must be verified
            authenticator Authenticator to use

        """
        if base_url == "":
            raise Exception("projet_url is not well formed or missing")
        self.base_url = base_url
        self.verify = verify

        # Used in _get, _post... to add common headers
        self.headers = {"user-agent": USER_AGENT}

        # build the client and login
        self.client = requests.session()
        if authenticator is None:
            # build a default authenticator based on the
            # given credentials
            authenticator = DefaultAuthenticator(
                self.base_url, username, password, verify=self.verify
            )
            # set the session to use for authentication

        authenticator.session = self.client
        self.login_data, self.cookie = authenticator.authenticate()

    def get_project_data(self, project_id):
        """Get the project hierarchy and some metadata.

        This mimics the browser behaviour when opening the project editor. This
        will open a websocket connection to the server to get the informations.

        Args:
            project_id (str): The id of the project
        """

        url = f"{self.base_url}/project/{project_id}"

        # use thread local storage to pass the project data
        storage = threading.local()

        class Namespace(BaseNamespace):
            def on_connect(self):
                logger.debug("[Connected] Yeah !!")

            def on_reconnect(self):
                logger.debug("[Reconnected] re-Yeah !!")

            def on_disconnect(self):
                logger.debug("[Disconnected]  snif!  ")

        def on_joint_project(*args):
            storage.project_data = args[1]

        def on_connection_rejected(*args):
            logger.debug("[connectionRejected]  oh !!!")

        headers = {"Referer": url}
        headers.update(self.headers)
        with SocketIO(
            self.base_url,
            verify=self.verify,
            Namespace=Namespace,
            cookies=self.cookie,
            headers=headers,
        ) as socketIO:

            def on_connection_accepted(*args):
                logger.debug("[connectionAccepted]  Waoh !!!")
                socketIO.emit(
                    "joinProject", {"project_id": project_id}, on_joint_project
                )

            socketIO.on("connectionAccepted", on_connection_accepted)
            socketIO.on("connectionRejected", on_connection_rejected)
            socketIO.wait(seconds=3)
        # NOTE(msimonin): Check return type
        # thuis must be a valid dict (eg not None)
        return storage.project_data

    def _request(self, verb, url, *args, **kwargs):
        headers = kwargs.get("headers", {})
        headers.update(self.headers)
        kwargs["headers"] = headers
        r = self.client.request(verb, url, *args, **kwargs)
        r.raise_for_status()
        return r

    def _get(self, url, *args, **kwargs):
        return self._request("GET", url, *args, **kwargs)

    def _post(self, url, *args, **kwargs):
        return self._request("POST", url, *args, **kwargs)

    def _delete(self, url, *args, **kwargs):
        return self._request("DELETE", url, *args, **kwargs)

    def download_project(self, project_id, *, path=".", keep_zip=False):
        """Download and unzip the project.

        Beware that this will overwrite any existing project file under path.

        Args:
            project_id (str): The id of the project to download
            path (Path): A valid path where the files will be saved

        Raises:
            Exception if the project can't be downloaded/unzipped.
        """
        url = f"{self.base_url}/project/{project_id}/download/zip"
        r = self._get(url, stream=True)
        logger.info(f"Downloading {project_id} in {path}")
        target_dir = Path(path)
        target_path = Path(target_dir, f"{project_id}.zip")
        with open(str(target_path), "wb") as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

        logger.info(f"Unzipping {project_id} in {path}")
        with zipfile.ZipFile(target_path) as zip_file:
            zip_file.extractall(path=path)

        if not keep_zip:
            target_path.unlink()

    def get_doc(self, project_id, doc_id):
        """Get a doc from a project .

        This mimics the browser behaviour when opening the project editor. This
        will open a websocket connection to the server to get the informations.

        Args:
            project_id (str): The id of the project
            doc_id (str): The id of the doc

        Returns:
            A string corresponding to the document.
        """

        url = f"{self.base_url}/project/{project_id}"

        # use thread local storage to pass the project data
        storage = threading.local()

        class Namespace(BaseNamespace):
            def on_connect(self):
                logger.debug("[Connected] Yeah !!")

            def on_reconnect(self):
                logger.debug("[Reconnected] re-Yeah !!")

            def on_disconnect(self):
                logger.debug("[Disconnected]  snif!  ")

        def on_connection_rejected(*args):
            logger.debug("[connectionRejected]  oh !!!")

        headers = {"Referer": url}
        headers.update(self.headers)
        with SocketIO(
            self.base_url,
            verify=self.verify,
            Namespace=Namespace,
            cookies=self.cookie,
            headers=headers,
        ) as socketIO:

            def on_joint_doc(*args):
                storage.doc_data = args[1]

            def on_joint_project(*args):
                storage.project_data = args[1]
                socketIO.emit("joinDoc", doc_id, {"encodeRanges": True}, on_joint_doc)

            def on_connection_accepted(*args):
                logger.debug("[connectionAccepted]  Waoh !!!")
                socketIO.emit(
                    "joinProject", {"project_id": project_id}, on_joint_project
                )

            socketIO.on("connectionAccepted", on_connection_accepted)
            socketIO.on("connectionRejected", on_connection_rejected)
            socketIO.wait(seconds=3)
        # NOTE(msimonin): Check return type
        return "\n".join(storage.doc_data)

    def get_file(self, project_id, file_id):
        """Get an individual file (e.g image).

        Args:
            project_id (str): The project id of the project where the file is
            file_id (str): The file id

        Returns:
            requests response

        Raises:
            Exception if the file can't be downloaded
        """
        url = f"{self.base_url}/project/{project_id}/file/{file_id}"
        r = self._get(url, data=self.login_data, verify=self.verify)
        r.raise_for_status()
        # TODO(msimonin): return type
        return r

    def get_document(self, project_id, doc_id):
        """Get a single document (e.g tex file).

        Note: This method requires a patch server side to expose the
        corresponding endpoint. So one shouldn't use this in general

        Args:
            project_id (str): The project id of the project where the document
                is
            doc_id (str): The document id

        Returns:
            requests response

        Raises:
            Exception if the file can't be downloaded
        """
        url = f"{self.base_url}/project/{project_id}/document/{doc_id}"
        r = self._get(url, data=self.login_data, verify=self.verify)

        # TODO(msimonin): return type
        return r

    def delete_file(self, project_id, file_id):
        """Delete a single file (e.g image).

        Args:
            project_id (str): The project id of the project where the file is
            file_id (str): The file id

        Returns:
            requests response

        Raises:
            Exception if the file can't be deleted
        """
        url = f"{self.base_url}/project/{project_id}/file/{file_id}"
        r = self._delete(url, data=self.login_data, verify=self.verify)
        r.raise_for_status()
        # TODO(msimonin): return type
        return r

    def delete_document(self, project_id, doc_id):
        """Delete a single document (e.g tex file).

        Args:
            project_id (str): The project id of the project where the document is
            doc_id (str): The document id

        Returns:
            requests response

        Raises:
            Exception if the file can't be deleted
        """
        url = f"{self.base_url}/project/{project_id}/doc/{doc_id}"
        r = self._delete(url, data=self.login_data, verify=self.verify)
        r.raise_for_status()
        # TODO(msimonin): return type

        return r

    def upload_file(self, project_id, folder_id, path):
        """Upload a file to sharelatex.

        Args:
            project_id (str): The project id
            folder_id (str): The parent folder
            path (str): Local path to the file

        Returns:
            requests response

        Raises:
            Exception if the file can't be uploaded
        """
        url = f"{self.base_url}/project/{project_id}/upload"
        filename = os.path.basename(path)
        # TODO(msimonin): handle correctly the content-type
        mime = filetype.guess(path)
        if not mime:
            mime = "text/plain"
        files = {"qqfile": (filename, open(path, "rb"), mime)}
        params = {
            "folder_id": folder_id,
            "_csrf": self.login_data["_csrf"],
            "qquid": str(uuid.uuid4()),
            "qqfilename": filename,
            "qqtotalfilesize": os.path.getsize(path),
        }
        r = self._post(url, params=params, files=files, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        if not response["success"]:
            raise Exception(f"Uploading {path} fails")
        return response

    def create_folder(self, project_id, parent_folder, name):
        """Create a folder on sharelatex.

        Args:
            project_id (str): The project id of the project to create the folder in
            parent_folder (str): The id of the folder to create the folder in
            name (str): Name of the folder

        Returns:
            response (dict) status of the request as returned by sharelatex

        Raises:
            Something wrong with sharelatex
            - 500 server error
            - 400 the folder already exists
        """
        url = f"{self.base_url}/project/{project_id}/folder"
        data = {
            "parent_folder_id": parent_folder,
            "_csrf": self.login_data["_csrf"],
            "name": name,
        }
        logger.debug(data)
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        return response

    def check_or_create_folder(self, metadata, folder_path):
        """Check if a given folder exists on sharelatex side.

        Create it recursively if needed and return its id.
        It looks in the metadata and create the missing directories.
        Make sure the metadata are up-to-date when calling this.

        Args:
            metadata (dict): The sharelatex metadata as a structure basis
            folder_path (str): The folder path

        Returns:
            The folder id of the deepest folder created.
        """
        try:
            folder = lookup_folder(metadata, folder_path)
            return folder["folder_id"]
        except StopIteration:
            logger.debug(f"{folder_path} not found, creation planed")

        parent_id = self.check_or_create_folder(metadata, os.path.dirname(folder_path))
        new_folder = self.create_folder(
            metadata["_id"], parent_id, os.path.basename(folder_path)
        )
        # This returns the id of the deepest folder
        return new_folder["_id"]

    def upload(self, path):
        """Upload a project (zip) to sharelatex.

        Args:
            path (str): Path to the zip file of a project.

        Returns:
             response (dict) status of the request as returned by sharelatex

        Raises:
             Exception if something is wrong with the zip of the upload.
        """
        url = f"{self.base_url}/project/new/upload"
        filename = os.path.basename(path)
        mime = "application/zip"
        files = {"qqfile": (filename, open(path, "rb"), mime)}
        params = {
            "_csrf": self.login_data["_csrf"],
            "qquid": str(uuid.uuid4()),
            "qqfilename": filename,
            "qqtotalfilesize": os.path.getsize(path),
        }
        r = self._post(url, params=params, files=files, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        if not response["success"]:
            raise Exception(f"Uploading {path} fails")
        return response

    def share(self, project_id, email, can_edit=True):
        """Send a invitation to share (edit/view) a project.

        Args:
            project_id (str): The project id of the project to share
            email (str): Email of the recipient of the invitation
            can_edit (boolean):True (resp. False) gives read/write (resp. read-only)
            access to the project

        Returns:
            response (dict) status of the request as returned by sharelatex

        Raises:
             Exception if something is wrong with the compilation
        """
        url = f"{self.base_url}/project/{project_id}/invite"
        data = {
            "email": email,
            "privileges": "readAndWrite" if can_edit else "readOnly",
            "_csrf": self.login_data["_csrf"],
        }
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        return response

    def compile(self, project_id):
        """Trigger a remote compilation.

        Note that this is run against the remote version not the local one.

        Args:
            project_id (str): The project id of the project to compile

        Returns:
            response (dict) status of the request as returned by sharelatex

        Raises:
             Exception if something is wrong with the compilation
        """
        url = f"{self.base_url}/project/{project_id}/compile"

        data = {"_csrf": self.login_data["_csrf"]}
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        if response["status"] != "success":
            raise CompilationError(response)
        return response

    def update_project_settings(self, project_id, **settings):
        """Update the project settings.

        Update the project settings.

        Args:
            project_id (str): The project id
            settings: the key/value of the settings to change (as keyword arguments)

        Examples:

        .. code:: python

            client.update_project_settings("5f326e4150cb80007f99a7c0",
                                           compiler="xelatex",
                                           name="newname")

        Returns

            The request response.
        """
        url = f"{self.base_url}/project/{project_id}/settings"

        data = {"_csrf": self.login_data["_csrf"]}
        data.update(settings)
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        return r

    def clone(self, project_id, project_name):
        """Copy a project.

        Args:
            project_id (str): The project id of the project to copy
            project_name (str): The project name of the destination project

        Returns:
            response (dict) containing the project_id of the created project

        Raises:
             Exception if something is wrong with the compilation
        """
        url = f"{self.base_url}/project/{project_id}/clone"

        data = {"_csrf": self.login_data["_csrf"], "projectName": project_name}
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        return response

    def new(self, project_name):
        """Create a new example project for the current user.

        Args:
            project_name (str): The project name of the project to create
        """
        url = f"{self.base_url}/project/new"

        data = {
            "_csrf": self.login_data["_csrf"],
            "projectName": project_name,
            "template": "example",
        }
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        return response

    def delete(self, project_id, *, forever=False):
        """Delete a project for the current user.

        Args:
            project_id (str): The project id of the project to delete
        """
        url = f"{self.base_url}/project/{project_id}"
        data = {"_csrf": self.login_data["_csrf"]}
        params = {"forever": forever}
        r = self._delete(url, data=data, params=params, verify=self.verify)
        r.raise_for_status()
        return r

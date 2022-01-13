import codecs
import datetime
import os
from typing import Mapping
import shutil
import zipfile

import pymongo
from bson.objectid import ObjectId


# Fetch the parameters from the env
# - Align the name with those from the overleaf container
# - Give precedence to the MONGO_URL if found
mongo_user = os.environ.get("MONGO_SHARELATEX_USER")
mongo_pass = os.environ.get("MONGO_SHARELATEX_PASSWORD")
mongo_url = os.environ.get("SHARELATEX_MONGO_URL")

mongo_host = os.environ.get("MONGO_HOST", "127.0.0.1")

if mongo_url is not None:
    _url = mongo_url
else:
    _url = f"mongodb://{mongo_user}:{mongo_pass}@{mongo_host}"

client = pymongo.MongoClient(_url)

DB = client["sharelatex"]


def _writeProjectFiles(
    project,
    destination_path="/tmp/",
    user_file_path="/var/lib/sharelatex/data/user_files",
):

    projectPath = os.path.join(destination_path, project["name"])
    project_id = project["_id"]

    def _writeFolders(folders, currentPath):
        for folder in folders:
            newPath = os.path.join(currentPath, folder["name"])
            if not os.path.exists(newPath):
                os.makedirs(newPath)
            for doc in folder["docs"]:
                doc_db = DB["docs"].find({"_id": doc["_id"]}).limit(1)
                filePath = os.path.join(newPath, doc["name"])
                with codecs.open(filePath, "w", "utf-8") as text_file:
                    text_file.write("\n".join(doc_db[0]["lines"]))
                print(doc["name"])
            for file_ref in folder["fileRefs"]:
                print(file_ref["name"])
                source = os.path.join(
                    user_file_path, str(project_id) + "_" + str(file_ref["_id"])
                )
                destination = os.path.join(newPath, file_ref["name"])
                try:
                    shutil.copyfile(source, destination)
                except IOError:
                    print(
                        "file {file} : {source} not found ".format(
                            file=file_ref["name"], source=source
                        )
                    )
                    print(
                        "unable to copy to {destination}".format(
                            destination=destination
                        )
                    )
            _writeFolders(folder["folders"], newPath)

    if not os.path.exists(projectPath):
        os.makedirs(projectPath)
    _writeFolders(project["rootFolder"], projectPath)


def getZipProject(project_uid, destination_path, user_file_path):
    """Make a zip of a project given a project uid"""
    projectPath = os.path.join(destination_path, project_uid)
    if not os.path.exists(projectPath):
        os.makedirs(projectPath)
    projects = DB["projects"].find({"_id": ObjectId(project_uid)})
    for project in projects:
        if not os.path.exists(projectPath):
            os.makedirs(projectPath)
        _writeProjectFiles(project, projectPath, user_file_path)

    def zipdir(path, zip_handle):
        for root, dirs, files in os.walk(path):
            for file in files:
                zip_handle.write(os.path.join(root, file))

    zipPath = os.path.join(destination_path, project_uid + ".zip")
    zip_handle = zipfile.ZipFile(zipPath, "w", zipfile.ZIP_DEFLATED)
    zipdir(projectPath, zip_handle)
    zip_handle.close()


def _get_projects_before_after(days: int, selector="$lt"):
    """return a dict containing in keys the ids of the inactive projects since the number
    of day passed in parameter, and in value their lastUpdated date"""

    ids_and_lastUpadted = {}
    projects = DB["projects"]

    date = datetime.datetime.now() - datetime.timedelta(days=days)
    inactive_projects = projects.find({"lastUpdated": {selector: date}})

    for inactive_project in inactive_projects:
        ids_and_lastUpadted[str(inactive_project["_id"])] = inactive_project[
            "lastUpdated"
        ]

    return ids_and_lastUpadted


def get_inactive_projects(days: int = 365) -> Mapping[str, datetime.datetime]:
    """Get the inactive projects for the last given days.

    Args:
        days: projects updated before now - days will be accounted as inactive

    Returns:
        Dict of project id mapped to the last updated date
    """
    # lastupdated earlier than the now() - days
    return _get_projects_before_after(days, selector="$lt")


def get_active_projects(days: int = 7) -> Mapping[str, datetime.datetime]:
    """Get the active projects in the last given days.

    Args:
        days: projects updated after now - days will be accounted as active

    Returns:
        Dict of project id mapped to the last updated date
    """
    # lastUpdated later than now() - days
    return _get_projects_before_after(days, selector="$gt")


def get_project_collaborators(project_id):
    """return a dict containing in keys the ids of the collaborators for
    the project of project_id id, and in values their mail adress"""
    project = DB["projects"].find({"_id": ObjectId(project_id)})
    result = {}

    for p in project:
        collab_refs = p["collaberator_refs"]
        for ref_id in collab_refs:
            collaborator = DB["users"].find({"_id": ref_id})
            for c in collaborator:
                result[str(ref_id)] = c["email"]

    return result


def changeMailAdress(old_adress, new_adress):
    # new_adress mustn't already be in DB
    if DB.users.find({"email": new_adress}).count() != 0:
        raise NameError("NewAdressAlreadyInDB")
    return DB.users.update_one({"email": old_adress}, {"$set": {"email": new_adress}})


def changeProjectOnwer(project_id, new_onwer_id):
    project = DB["projects"].find({"_id": ObjectId(project_id)}).limit(1)
    if project.count() == 0:
        raise NameError("ProjectIdNotDB")
    users = DB.users.find({"_id": ObjectId(new_onwer_id)})
    if users.count() == 0:
        raise NameError("UserIdNotInDB")
    return DB["projects"].update_one(
        {"_id": ObjectId(project_id)}, {"$set": {"owner_ref": ObjectId(new_onwer_id)}}
    )

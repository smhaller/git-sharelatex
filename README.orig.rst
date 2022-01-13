Python-sharelatex is a library to interact with https://sharelatex.irisa.fr. It
also includes a command line tools to sync your remote project with Git. This
allows you to work offline on your project and later sync your local copy with
the remote one.

Links
-----

- Source: https://gitlab.inria.fr/sed-rennes/sharelatex
- Documentation: https://sed-rennes.gitlabpages.inria.fr/sharelatex/python-sharelatex
- Mattermost: https://mattermost.irisa.fr/sed-rba/channels/sharelatex-users
- Pypi: https://pypi.org/project/sharelatex/


**The code is currently experimental and under development. Use it with caution.**


Installation
------------


.. code:: bash

    # Latest stable version
    pip install sharelatex

    # Development version
    git clone https://gitlab.inria.fr/sed-rennes/sharelatex/python-sharelatex
    cd python-sharelatex
    pip install [-e] .

Compatibility notes
-------------------

The tool is targetting the community edition of ShareLatex/Overleaf.
More specifically one specific version of the tool is targetting one specific
version of ShareLatex/Overleaf CE version. Roughly we have the following mapping:


.. list-table:: compatibility
   :widths: 25 25
   :header-rows: 1

   * - python-sharelatex
     - sharelatex/overleaf
   * - 0.Y.Z
     - 1.2.1
   * - 1.Y.Z
     - 2.3.1
   * - 2.Y.Z
     - 3.0.1

Note on passwords management
----------------------------

Passwords are stored in your keyring service (Keychain, Kwallet ...) thanks to
the `keyring <https://pypi.org/project/keyring/>`_ library. Please refer to the
dedicated documentation for more information.

Quick examples
--------------

Display the possible actions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`slatex` is a subcommand of git that calls the ``git-slatex`` programm shipped by this project.

.. code:: bash

    $) git slatex

    Usage: git-slatex [OPTIONS] COMMAND [ARGS]...

    Options:
      --help  Show this message and exit.

    Commands:
      clone    Get (clone) the files from sharelatex projet URL and crate a...
      compile  Compile the remote version of a project
      new      Upload the current directory as a new sharelatex project
      pull     Pull the files from sharelatex.
      push     Push the commited changes back to sharelatex


For instance you can get the help on a specific sub-command with the following:

.. code:: bash

   git slatex clone --help


Get an existing project on slatex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

    mkdir test
    cd test
    # download all files of a remote project
    git slatex clone <project_URL> <local_path_to_project>


Editing and pushing back to slatex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


.. code:: bash

    # edit your files
    # commit, commit, commit ...
    #
    # Push back your change to sharelatex
    git slatex push

Concurrent updates may occur between your local files (because you changed them)
and the remote ones (because you collaborators changed them). So before pushing,
we try to make sure the merge between the remote copy and the local ones is ok.
You'll have to resolve the conflict manually (as usual with Git) and attempt a
new push.

Pull changes from sharelatex to local (like a git pull)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


.. code:: bash

    # Pull changes from sharelatex
    git slatex pull




Create a remote project from a local git
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   git slatex new <base_server_URL> <new_project_name>

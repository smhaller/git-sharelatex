# Git / Sharelatex Integration

This repo contains a python library to interact with a sharelatex server via git.

The inital idea for this implementation was taken from 
[inria](https://gitlab.inria.fr/sed-rennes/sharelatex/python-sharelatex/).

This version works with ldap-overleaf-sl and more general with sharelatex 3.0.1.

## Installation
git clone https://github.com/smhaller/git-sharelatex
cd git-sharelatex
pip install [-e] .

### On older systems
pip3 install [-e] .


## Adaptations

- works now default with the login of sharelatex (including some fixes and shortcuts)
- added some os checks (keyring, files)
- added missing dependencies




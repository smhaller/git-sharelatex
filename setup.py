# -*- coding: utf-8 -
import os
from setuptools import setup


here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open(os.path.join(here, "sharelatex", "__version__.py")) as f:
    exec(f.read(), about)

setup(version=about["__version__"])

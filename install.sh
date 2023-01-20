#!/bin/bash

# pyenv is used to manage Python version.
# It is setup in $HOME/.bash_aliases:-
#
# # Load pyenv automatically by appending
# export PYENV_ROOT="$HOME/.pyenv"
# command -v pyenv >/dev/null
# eval "$(pyenv init -)"
# # Load pyenv-virtualenv automatically by adding
# eval "$(pyenv virtualenv-init -)"

# Install packages required by pylei
python3 -m pip install -r requirement.txt

# Install pylei as editable package
# setup.cfg and setup.py are settings for installing the local package
# into Python system
# -e : editable allowing source code change without reinstalling
python3 -m pip install -e .

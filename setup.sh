#!/bin/bash

# Install specific Python version
pyenv install 3.11.4 -s
pyenv global 3.11.4

# Install dependencies
pip install -r requirements.txt

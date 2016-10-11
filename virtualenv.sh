#!/bin/bash

virtualenv -p /usr/local/bin/python3 env
source env/bin/activate
pip install -r requirements.txt

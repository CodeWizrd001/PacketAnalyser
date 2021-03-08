# Packet Analyser
Dependencies places in pyproject.toml file  
----------------
## Setup
~~~bash
# Poetry 
python3 -m pip install poetry           # or
pip3 install poetry
~~~
or
~~~bash
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3 -
~~~
----------------
## Virtual Environment
~~~bash
# Update or install dependencies
poetry install

# Enter Virtual Environment
poetry shell

# Add Dependency
poetry add <package-name>
~~~

## Run Tool
Has to be run as super user
~~~bash
python sniff.py -i <interface_name>
~~~

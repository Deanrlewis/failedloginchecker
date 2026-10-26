# failedloginchecker
A short python script that scans a log and flags IP addresses with repeated failed attempts.

# usage
python failedlogincheck.py sample_auth.log
requires python 3. standard library.

it parses each line
counts failures
flags any IP above a certain limit
lists the 3 most targeted accounts

## secure coding
validates input
resource limits
error handling
sanitization


## Limitations
this is a learning project for me and something I'm using to start practicing
It is not a substitute for an actual monitoring tool
sample_auth.log is made up data for the purposes of this project

## Built with AI assistance, then reviewed, tested, and modified by me.

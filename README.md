# Threat-Scope
A real time network monitor that tries to detect cyber threats… sometimes

ThreatScope is a Python program that watches your network and attempts to spot sketchy activity.

It can show things like:

Spikes in upload/download

Lots of connections at once

Suspicious IPs

Weird traffic from random countries

But: it’s not a professional firewall or antivirus don’t rely on it to keep hackers and or anything out, It’s mostly for fun,

Features:

Real-time dashboard with spinning animations

“Hair trigger” detection for the overly cautious

Baseline learning so it knows what “normal” is (kind of)

Optional auto blocking… may or may not work perfectly

Cool ASCII banners for branding

Installation & Usage:

Clone the repo:

git clone https://github.com/Usernamerobot/ThreatScope.git


Install dependencies:

pip install -r requirements.txt


Run the program:

python threatscope.py


Disclaimer:
This program is mostly for fun and learning. It may report false positives and is not a replacement for real security software.

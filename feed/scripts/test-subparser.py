# Loads _subparser from the current directory and parses SRT and TTML.
# Runs on Python 2.7 and 3.x (the python of the test container).
import os
import sys

# the module lies in the current directory, a script only searches its own one
sys.path.insert(0, os.getcwd())
import _subparser  # noqa: E402

print("Python %s, _subparser %s" % (sys.version.split()[0], _subparser.version()))
assert float(_subparser.version()) >= 0.5, "the setup wants >= 0.5"

srt = "1\n00:00:01,000 --> 00:00:02,000\nHello world\n\n2\n00:00:03,000 --> 00:00:04,500\n<i>second</i> cue\n\n"
r = _subparser.parse(srt, 0, 1, 1, 12, 138)
print("srt: %r" % (r,))
assert len(r["list"]) == 2 and r["list"][1]["start"] == 3000 and r["list"][1]["end"] == 4500

ttml = ('<?xml version="1.0" encoding="UTF-8"?>'
        '<tt xmlns="http://www.w3.org/ns/ttml"><body><div>'
        '<p begin="00:00:01.000" end="00:00:03.000">Ampersand &amp; entity</p>'
        '<p begin="00:00:04.000" end="00:00:06.000">second cue</p>'
        '</div></body></tt>')
r = _subparser.parse(ttml, 0, 1, 1, 12, 138)
print("ttml: %r" % (r,))
assert len(r["list"]) == 2 and "&" in r["list"][0]["text"]
print("ok")

import urllib2

__version__ = "1.0.1"

try:
    
    r = urllib2.urlopen("https://raw.githubusercontent.com/prodigysml/Dr.-Watson/master/__version__.py", timeout=3)
    if not __version__ == r.read().split('"')[1]:
        print("Dr. Watson is out of date. Please download the latest version from GitHub. https://prodigysml/Dr.-Watson/")
except:
    pass
# Dr. Watson

Dr. Watson is a simple Burp Suite extension that helps find assets, keys, subdomains, IP addresses, and other useful information! It's your very own discovery side kick, the Dr. Watson to your Sherlock! 

[![License](https://img.shields.io/badge/license-GPL3-_red.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html) [![Twitter](https://img.shields.io/badge/twitter-@sml555__-blue.svg)](https://twitter.com/sml555_) ![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)

# How Does Dr. Watson Work?

Dr. Watson takes regexes from the issues_library.json file and attempts to match said regexes with responses within Burp Suite. Once it matches a regex, it raises an issue with the severity defined in the config, as a finding for the target host. It is simple, sweet, and easy to use! 

# Setup - Installing for Burp Suite Pro
## Setting Up Jython
1. Download the latest standalone version of [jython](https://www.jython.org/download)
2. Navigate to Extender -> Options
3. Navigate to the "Python Environment" section
4. Click "Select File" and select the previously downloaded file

## Installing the Plugin
1. Navigate to Extender -> Extensions
2. Click the "Add" button
3. Change the "Extension Type" to "Python"
4. Select the plugin python file within the "Extension file" field
5. Click "Next"
6. Enjoy the plugin!

# How to Use The Plugin

1. Install the plugin
2. Add any domain you want analysed into scope (if not in scope, it will not be analysed, ensuring performance is not hindered immensely)
3. Navigate / crawl through the website and observe the plugin creates issues for different resources identified. 

# Authors and Thanks
Originally written by Sajeeb Lohani ([sml555](https://twitter.com/sml555_)). I would like to thank the following for helping with the project:
* BugCrowd HUNT for the Jython installation steps
* Redhunt Labs for the original plugin and the idea
* TruffleHog Regexes and git-all-secrets for the regexes

# Contributions
Contributions to this project are very welcome. If you're a newcomer to open source and would like some help in doing so, feel free to reach out to me on twitter ([@sml555_](https://twitter.com/sml555_)) and I'll assist wherever I can. 

# Dr. Watson: Burp Suite Extension that helps you find assets, keys, and useful information. Your very own Burp side kick!
# By: Sajeeb Lohani (sml555)
# Twitter: https://twitter.com/sml555_

# Code Credits:
# Redhunt Labs for making the original asset discovery plugin
# OpenSecurityResearch CustomPassiveScanner: https://github.com/OpenSecurityResearch/CustomPassiveScanner
# PortSwigger example-scanner-checks: https://github.com/PortSwigger/example-scanner-checks


from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re
import json

# Implement BurpExtender to inherit from multiple base classes
# IBurpExtender is the base class required for all extensions
# IScannerCheck lets us register our extension with Burp as a custom scanner check
class BurpExtender(IBurpExtender, IScannerCheck):

    # The only method of the IBurpExtender interface.
    # This method is invoked when the extension is loaded and registers
    # an instance of the IBurpExtenderCallbacks interface
    def	registerExtenderCallbacks(self, callbacks):
        # Put the callbacks parameter into a class variable so we have class-level scope
        self._callbacks = callbacks

        # Set the name of our extension, which will appear in the Extender tool when loaded
        self._callbacks.setExtensionName("Dr. Watson")

        # Register our extension as a custom scanner check, so Burp will use this extension
        # to perform active or passive scanning and report on scan issues returned
        self._callbacks.registerScannerCheck(self)

        library_file = open("issues_library.json")
        library_file = library_file.read()

        self.library = json.loads(library_file)

        print(self.library[4][0])
        print("http(?:s)://[^><\.\'\" \n\)]+.[^><\.\'\" \n\)]+.[^><\.\'\" \n\)]+.digitaloceanspaces.com")

        return

    # This method is called when multiple issues are reported for the same URL
    # In this case we are checking if the issue detail is different, as the
    # issues from our scans include affected parameters/values in the detail,
    # which we will want to report as unique issue instances
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    # Implement the doPassiveScan method of IScannerCheck interface
    # Burp Scanner invokes this method for each base request/response that is passively scanned.
    def doPassiveScan(self, baseRequestResponse):
        # Local variables used to store a list of ScanIssue objects
        scan_issues = list()
        tmp_issues = list()

        # Create an instance of our CustomScans object, passing the
        # base request and response, and our callbacks object
        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)

        for issue in self.library:
            scan_issues += self._CustomScans.findRegEx(issue[0], issue[1], issue[2], issue[3])

            scan_issues += tmp_issues

            tmp_issues = list()

        # Finally, per the interface contract, doPassiveScan needs to return a
        # list of scan issues, if any, and None otherwise
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

class CustomScans:
    def __init__(self, requestResponse, callbacks):
        # Set class variables with the arguments passed to the constructor
        self._requestResponse = requestResponse
        self._callbacks = callbacks

        # Get an instance of IHelpers, which has lots of useful methods, as a class
        # variable, so we have class-level scope to all the helper methods
        self._helpers = self._callbacks.getHelpers()

        # Put the parameters from the HTTP message in a class variable so we have class-level scope
        self._params = self._helpers.analyzeRequest(requestResponse.getRequest()).getParameters()
        return

    # This is a custom scan method to Look for all occurrences in the response
    # that match the passed regular expression
    def findRegEx(self, regex, issuename, issuelevel, issuedetail):
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = len(response)

        # Only check responses for 'in scope' URLs

        if self._callbacks.isInScope(self._helpers.analyzeRequest(self._requestResponse).getUrl()):

            # Compile the regular expression, telling Python to ignore EOL/LF
            myre = re.compile(regex, re.DOTALL)


            # Using the regular expression, find all occurrences in the base response
            match_vals = myre.findall(self._helpers.bytesToString(response))

            for ref in match_vals:
                url = self._helpers.analyzeRequest(self._requestResponse).getUrl()

                # Don't add the source domain to issues
                if ref.split("//")[-1].split("/")[0].split('?')[0].split(':')[0] == str(url).split("//")[-1].split(":")[0].split('?')[0]:
                    continue

                # For each matched value found, find its start position, so that we can create
                # the offset needed to apply appropriate markers in the resulting Scanner issue
                offsets = []
                start = self._helpers.indexOf(response,
                                    ref, True, 0, responseLength)
                offset[0] = start
                offset[1] = start + len(ref)
                offsets.append(offset)


                # Create a ScanIssue object and append it to our list of issues, marking
                # the matched value in the response.

                if (issuename == "Asset Discovered: IP"):
                    print "IP: "+ref
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                elif (issuename == "Asset Discovered: Domain"):
                    ref=ref.split("//")[-1].split("/")[0].split('?')[0]
                    print "Domain: "+ref
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                elif (issuename == "Asset Discovered: Subdomain"):
                    ref=ref.split("//")[-1].split("/")[0].split('?')[0]
                    domain = str(url).split("//")[-1].split(":")[0].split('?')[0]
                    coredomain = str(domain).rsplit('.')[-2]+"."+str(domain).rsplit('.')[-1]
                    if not coredomain in ref or ref==coredomain:
                        continue
                    print "Subdomain: "+ref
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                elif (issuename == "Asset Discovered: S3 Bucket"):
                    ref=ref.split(" ")[0].split('/')[2].split('.')[0]
                    print "S3 Bucket: "+ref
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                elif (issuename == "Asset Discovered: DigitalOcean Space"):
                    ref=ref.split('/')[2].split('.')[0]
                    print "DigitalOcean Space: "+ref
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                elif (issuename == "Asset Discovered: Azure Blob"):
                    ref=ref.split(" ")[0].split('/')[2].split(".")[0]+":"+ref.split(" ")[0].split('/')[3]
                    print "Azure Blob: "+ref
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace("$asset$", ref)))

        return (scan_issues)

# Implementation of the IScanIssue interface with simple constructor and getter methods
class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"
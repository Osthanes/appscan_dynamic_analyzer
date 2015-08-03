#!/usr/bin/python

#***************************************************************************
# Copyright 2015 IBM
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#***************************************************************************

import json
import logging
import logging.handlers
import os
import os.path
import requests
import sys
import time
import timeit
from datetime import datetime
from subprocess import call, Popen, PIPE
import python_utils

DYNAMIC_ANALYSIS_SERVICE='AppScan Dynamic Analyzer'
DEFAULT_SERVICE=DYNAMIC_ANALYSIS_SERVICE
DEFAULT_SERVICE_PLAN="standard"
DEFAULT_SERVICE_NAME=DEFAULT_SERVICE
DEFAULT_SCANNAME="webscan"
DEFAULT_APPSCAN_SERVER="https://appscan.ibmcloud.com"

# time to sleep between checks when waiting on pending jobs, in seconds
SLEEP_TIME=15

# scan info, loaded from ENV
APPSCAN_SERVER = ""
AD_BASE_URL = None
AD_USER = None
AD_PWD = None
IDS_PROJECT_NAME = None
# our auth token
APPSCAN_TOKEN = None

# some appscan defines - production scan tries harder to be
# nondestructive.  staging is more willing to submit posts, deletes, etc
APPSCAN_SCAN_TYPE_PRODUCTION = 0
APPSCAN_SCAN_TYPE_STAGING    = 1

# check cli args, set globals appropriately
def parse_args ():
    global APPSCAN_SERVER, AD_BASE_URL, AD_USER, AD_PWD, IDS_PROJECT_NAME
    parsed_args = {}
    parsed_args['loginonly'] = False
    parsed_args['checkstate'] = False
    parsed_args['debug'] = False
    parsed_args['help'] = False
    for arg in sys.argv:
        if arg == "--loginonly":
            # only login, no scanning or submission
            parsed_args['loginonly'] = True
        if arg == "--checkstate":
            # just check state of existing jobs, don't scan or submit
            # any new ones
            parsed_args['checkstate'] = True
        if arg == "--debug":
            # enable debug mode, can also be done with python_utils.DEBUG env var
            parsed_args['debug'] = True
            python_utils.DEBUG = "1"
        if (arg == "--help") or (arg == "-h"):
            # just print help and return
            parsed_args['help'] = True

    # load env vars
    APPSCAN_SERVER = os.getenv('APPSCAN_ENV', DEFAULT_APPSCAN_SERVER)
    AD_BASE_URL = os.environ.get('AD_BASE_URL')
    AD_USER = os.environ.get('AD_USER')
    AD_PWD = os.environ.get('AD_PWD')
    IDS_PROJECT_NAME = os.environ.get('IDS_PROJECT_NAME')
    if IDS_PROJECT_NAME:
        IDS_PROJECT_NAME = IDS_PROJECT_NAME.replace(" | ", "-")

    return parsed_args

# print a quick usage/help statement
def print_help ():
    print "usage: appscan_check.py [options]"
    print
    print "\toptions:"
    print "\t   --loginonly    : get credentials and login to appscan only"
    print "\t   --checkstate   : check state of existing job(s), no new submission"
    print "\t   --debug        : get additional debug output"
    print "\t   --help         : print this help message and exit"
    print
    print "\texpected env vars:"
    print "\t   AD_BASE_URL    : base url to begin scanning from (required)"
    print "\t   BINDING_APP    : the app containing the bound route for the base URL (required)"
    print "\t   APPSCAN_SERVER : the appscan server to run commands against (optional)"
    print "\t   AD_USER        : userid to login to the scanned pages, if necessary (optional)"
    print "\t   AD_PWD         : password to login to the scanned pages, if necessary (optional)"
    print "\t   WAIT_TIME      : time in minutes to wait for the scan to complete (optional, default 5)"
    print



# create a template for a current scan.  this will be in the format
# "<scanname>-<version>-" where scanname comes from env var 
# 'SUBMISSION_NAME', and version comes from env var 'APPLICATION_VERSION'
def get_scanname_template (include_version=True):
    # check the env for name of the scan, else use default
    if os.environ.get('SUBMISSION_NAME'):
        scanname=os.environ.get('SUBMISSION_NAME')
    elif IDS_PROJECT_NAME:
        scanname = IDS_PROJECT_NAME
    else:
        scanname=DEFAULT_SCANNAME

    # if no version, will end with a dash - this is expected (and used)
    # for matching old versions
    scanname = scanname + "-"
    if include_version:
        # if we have an application version, append it to the scanname
        if os.environ.get('APPLICATION_VERSION'):
            scanname = scanname + os.environ.get('APPLICATION_VERSION')
        else:
            # need a version, don't have one, set to 0
            scanname = scanname + "0"

    return scanname

# given userid and password, attempt to authenticate to appscan for
# future calls
def appscan_login (userid, password):
    global APPSCAN_TOKEN

    url = "%s/api/BlueMix/Account/BMAPILogin" % APPSCAN_SERVER
    body = "{\"Bindingid\": \"%s\", \"Password\": \"%s\"}" % (userid, password)
    xheaders = {
        'content-type': 'application/json',
    }

    if python_utils.DEBUG:
        python_utils.LOGGER.debug("Sending request \"" + str(url) + "\" with body \"" + str(body) + "\" and headers \"" + str(xheaders) + "\"")
    res = requests.post(url, data=body, headers=xheaders)
    if python_utils.DEBUG:
        python_utils.LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

    if res.status_code != 200:
        raise Exception("Unable to login to Dynamic Analysis service, status code " + str(res.status_code))

    rj = res.json()
    APPSCAN_TOKEN = rj["Token"]
    if not APPSCAN_TOKEN:
        raise Exception("Unable to login to Dynamic Analysis service")
    else:
        APPSCAN_TOKEN = "Bearer " + APPSCAN_TOKEN

# submit a base url to appscan for analysis
def appscan_submit (baseurl, baseuser=None, basepwd=None, oldjobs=None):
    if not baseurl:
        raise Exception("No Base URL to scan")

    if not APPSCAN_TOKEN:
        raise Exception("Attempted submit with no valid login token")

#TODO: To rescan, see about using /Rescan instead of /Scan
#TODO: To rescan you have to provide the jobID of what you are rescanning
#TODO: Recan is free for a month... you can get data on job about time remaining on free rescans

#TODO: Follow-up on UserAgreeToPay
    url = "%s/api/BlueMix/DynamicAnalyzer/Scan" % APPSCAN_SERVER
    body_struct = {}
    body_struct["ScanName"] = get_scanname_template()
    body_struct["StartingUrl"] = baseurl
    body_struct["ScanType"] = APPSCAN_SCAN_TYPE_PRODUCTION
    if baseuser:
        body_struct["LoginUser"] = baseuser
    if basepwd:
        body_struct["LoginPassword"] = basepwd
    body_struct["UserAgreeToPay"] = True
    body_struct["Locale"] = "en-us"

    body = json.dumps(body_struct)
    xheaders = {
        'content-type': 'application/json',
        'Authorization': APPSCAN_TOKEN

    }

    if python_utils.DEBUG:
        python_utils.LOGGER.debug("Sending request \"" + str(url) + "\" with body \"" + str(body) + "\" and headers \"" + str(xheaders) + "\"")
    res = requests.post(url, data=body, headers=xheaders)
    if python_utils.DEBUG:
        python_utils.LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

    if (res.status_code < 200) or (res.status_code > 204):
        msg = "Error submitting scan to Dynamic Analysis service (list), status code " + str(res.status_code)
        if res.text:
            try:
                res_err = json.loads(res.text)
                if res_err and res_err["Message"]:
                    msg = msg + " with message \"" + str(res_err["Message"]) + "\""
            except Exception:
                if python_utils.DEBUG:
                    python_utils.LOGGER.debug("unable to parse returned error data")
        raise Exception(msg)

    rj = res.json()
    scanlist = []
    scanlist.append(rj["JobId"])

    return scanlist


# get appscan list of current jobs
def appscan_list ():
    if not APPSCAN_TOKEN:
        raise Exception("Attempted submit with no valid login token")

    url = "%s/api/BlueMix/DynamicAnalyzer/Scans/" % APPSCAN_SERVER
    xheaders = {
        'content-type': 'application/json',
        'Authorization': APPSCAN_TOKEN

    }

    if python_utils.DEBUG:
        python_utils.LOGGER.debug("Sending request \"" + str(url) + "\" with headers \"" + str(xheaders) + "\"")
    res = requests.get(url, headers=xheaders)
    if python_utils.DEBUG:
        python_utils.LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

    if res.status_code != 200:
        raise Exception("Unable to communicate with Dynamic Analysis service (list), status code " + str(res.status_code))

    rj = res.json()
    scanlist = []
    for scan in rj:
        scanlist.append(scan["JobId"])

    return scanlist

# translate a job state to a pretty name
def get_state_name (state):
    return {
        0 : "Pending",
        1 : "Starting",
        2 : "Running",
        3 : "FinishedRunning",
        4 : "FinishedRunningWithErrors",
        5 : "PendingSupport",
        6 : "Ready",
        7 : "ReadyIncomplete",
        8 : "FailedToScan",
        9 : "ManuallyStopped",
        10 : "None",
        11 : "Initiating",
        12 : "MissingConfiguration",
        13 : "PossibleMissingConfiguration"
    }.get(state, "Unknown")

# given a state, is the job completed
def get_state_completed (state):
    return {
        0 : False,
        1 : False,
        2 : False,
        3 : True,
        4 : True,
        5 : False,
        6 : True,
        7 : True,
        8 : True,
        9 : True,
        10 : True,
        11 : False,
        12 : True,
        13 : True
    }.get(state, True)

# given a state, was it completed successfully
def get_state_successful (state):
    return {
        0 : False,
        1 : False,
        2 : False,
        3 : True,
        4 : False,
        5 : False,
        6 : True,
        7 : False,
        8 : False,
        9 : False,
        10 : False,
        11 : False,
        12 : False,
        13 : False
    }.get(state, False)

# parse a key=value line, return value
def parse_key_eq_val (line):
    if line == None:
        return None

    eqIndex = line.find("=");
    if eqIndex != -1:
        return line[eqIndex+1:]
    else:
        return None

# extended info on a current appscan job.  this returns a dict for a json block like:
#
#  {
#    "StartingUrl": "string",
#    "LoginUser": "string",
#    "NVisitedPages": 0,
#    "NUnvisitedPages": 0,
#    "NTestedEntities": 0,
#    "NEntities": 0,
#    "JobId": "string",
#    "ScanId": "string",
#    "Name": "string",
#    "CreatedAt": "string",
#    "ScanEndTime": "string",
#    "UserMessage": "string",
#    "PredefinedMessageKey": "string",
#    "JobStatus": 0,
#    "NIssuesFound": 0,
#    "Result": 0,
#    "ReadStatus": 0,
#    "Progress": 0,
#    "ParentJobId": "string",
#    "EnableMailNotifications": true,
#    "FreeRescanEndDate": "string",
#    "OrigScanDate": "string",
#    "LastRescanDate": "string",
#    "NHighIssues": 0,
#    "NMediumIssues": 0,
#    "NLowIssues": 0,
#    "NInfoIssues": 0
#  }
#
def appscan_info (jobid):

    if not APPSCAN_TOKEN:
        raise Exception("Attempted submit with no valid login token")

    url = "%s/api/BlueMix/DynamicAnalyzer/Scans/%s" % (APPSCAN_SERVER, str(jobid))
    xheaders = {
        'content-type': 'application/json',
        'Authorization': APPSCAN_TOKEN

    }

    if python_utils.DEBUG:
        python_utils.LOGGER.debug("Sending request \"" + str(url) + "\" with headers \"" + str(xheaders) + "\"")
    res = requests.get(url, headers=xheaders)
    if python_utils.DEBUG:
        python_utils.LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

    if res.status_code != 200:
        raise Exception("Unable to communicate with Dynamic Analysis service (list), status code " + str(res.status_code))

    for job in res.json():
        if job["JobId"] == jobid:
            return job

    raise Exception("Job not found")

# get status of a given job
def appscan_status (jobid):
    if jobid == None:
        raise Exception("No jobid to check status")

    job = appscan_info(jobid)

    if job:
        return job["JobStatus"]

    raise Exception("Unable to find job to check status")

# if the job we would run is already up (and either pending or complete),
# we just want to get state (and wait for it if needed), not create a whole
# new submission.  for the key, we use the job name, compared to the
# name template as per get_scanname_template()
def check_for_existing_job ( ignore_older_jobs = True):
    alljobs = appscan_list()
    if alljobs == None:
        # no jobs, ours can't be there
        return None

    # get the name we're looking for
    job_name = get_scanname_template( include_version = ignore_older_jobs )
    joblist = []
    found = False
    for jobid in alljobs:
        results = appscan_info(jobid)
        if results["Name"].startswith(job_name):
            joblist.append(jobid)
            found = True

    if found:
        return joblist
    else:
        return None

# wait for a given set of scans to complete and, if successful,
# download the results
def wait_for_scans (joblist):
    # were all jobs completed on return
    all_jobs_complete = True
    # number of high sev issues in completed jobs
    high_issue_count = 0
    med_issue_count = 0
    dash = python_utils.find_service_dashboard(DYNAMIC_ANALYSIS_SERVICE)
    for jobid in joblist:
        try:
            while True:
                state = appscan_status(jobid)
                python_utils.LOGGER.info("Job " + str(jobid) + " in state " + get_state_name(state))
                if get_state_completed(state):
                    results = appscan_info(jobid)
                    if get_state_successful(state):
                        high_issue_count += results["NHighIssues"]
                        med_issue_count += results["NMediumIssues"]
                        python_utils.LOGGER.info("Analysis successful (" + results["Name"] + ")")
                        #print "\tOther Message : " + msg
                        #appscan_get_result(jobid)
                        print python_utils.LABEL_GREEN + python_utils.STARS
                        print "Analysis successful for job \"" + results["Name"] + "\""
                        print "\tHigh Severity Issues   : " + str(results["NHighIssues"])
                        print "\tMedium Severity Issues : " + str(results["NMediumIssues"])
                        print "\tLow Severity Issues    : " + str(results["NLowIssues"])
                        print "\tInfo Severity Issues   : " + str(results["NInfoIssues"])
                        if dash != None:
                            print "See detailed results at: " + python_utils.LABEL_COLOR + " " + dash
                        print python_utils.LABEL_GREEN + python_utils.STARS + python_utils.LABEL_NO_COLOR
                    else: 
                        python_utils.LOGGER.info("Analysis unsuccessful (" + results["Name"] + ") with message \"" + results["UserMessage"] + "\"")

                    break
                else:
                    time_left = get_remaining_wait_time()
                    if (time_left > SLEEP_TIME):
                        time.sleep(SLEEP_TIME)
                    else:
                        # ran out of time, flag that at least one job didn't complete
                        all_jobs_complete = False
                        # get what info we can on this job
                        results = appscan_info(jobid)
                        # notify the user
                        print python_utils.LABEL_RED + python_utils.STARS
                        print "Analysis incomplete for job \"" + results["Name"] + "\""
                        print "\t" + str(results["Progress"]) + "% complete"
                        if dash != None:
                            print "Track current state and results at: " + python_utils.LABEL_COLOR + " " + dash
                        print python_utils.LABEL_RED + "Increase the time to wait and rerun this job. The existing analysis will continue and be found and tracked."
                        print python_utils.STARS + python_utils.LABEL_NO_COLOR

                        # and continue to get state for other jobs
                        break
        except Exception, e:
            # bad id, skip it
            if python_utils.DEBUG:
                python_utils.LOGGER.debug("exception in wait_for_scans: " + str(e))

    return all_jobs_complete, high_issue_count, med_issue_count


# begin main execution sequence

try:
    parsed_args = parse_args()
    if parsed_args['help']:
        print_help()
        sys.exit(0)

    python_utils.LOGGER = python_utils.setup_logging()
    python_utils.WAIT_TIME = python_utils.get_remaining_wait_time(first = True)
    # send slack notification 
    if os.path.isfile("%s/utilities/sendMessage.sh" % python_utils.EXT_DIR):
        command='{path}/utilities/sendMessage.sh -l info -m \"Starting dynamic security scan\"'.format(path=python_utils.EXT_DIR)
        if python_utils.DEBUG:
            print "running command " + command 
        proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate();
        python_utils.LOGGER.debug(out)
    else:
        if python_utils.DEBUG:
            print "sendMessage.sh not found, notifications not attempted"

    python_utils.LOGGER.info("Getting credentials for Dynamic Analysis service")
    creds = python_utils.get_credentials_from_bound_app(service=DYNAMIC_ANALYSIS_SERVICE, plan=DEFAULT_SERVICE_PLAN)
    python_utils.LOGGER.info("Connecting to Dynamic Analysis service")
    appscan_login(creds['bindingid'],creds['password'])

    # allow testing connection without full job scan and submission
    if parsed_args['loginonly']:
        python_utils.LOGGER.info("LoginOnly set, login complete, exiting")
        endtime = timeit.default_timer()
        print "Script completed in " + str(endtime - python_utils.SCRIPT_START_TIME) + " seconds"
        sys.exit(0)

    # see if we have related jobs (need this for both paths)
    joblist = check_for_existing_job(ignore_older_jobs=False)
    # if checkstate, don't really do a scan, just check state of current outstanding ones
    if parsed_args['checkstate']:
        # for checkstate, don't wait, just check current
        python_utils.WAIT_TIME = 0
        if joblist == None:
            # no related jobs, get whole list
            joblist = appscan_list()
    else:
        # save list of old jobs, will need this if it's a rescan
        old_joblist = joblist
        # if the job we would run is already up (and either pending or complete),
        # we just want to get state (and wait for it if needed), not create a whole
        # new submission (check current version only at this point)
        joblist = check_for_existing_job(ignore_older_jobs=True)
        if joblist == None:
            python_utils.LOGGER.info("Submitting URL for analysis")
            joblist = appscan_submit(AD_BASE_URL, baseuser=AD_USER, basepwd=AD_PWD, oldjobs=old_joblist)
            python_utils.LOGGER.info("Waiting for analysis to complete")
        else:
            python_utils.LOGGER.info("Existing job found, connecting")

    # check on pending jobs, waiting if appropriate
    all_jobs_complete, high_issue_count, med_issue_count = wait_for_scans(joblist)

    # prebuild common substrings
    dash = python_utils.find_service_dashboard(DYNAMIC_ANALYSIS_SERVICE)
    # if we didn't successfully complete jobs, return that we timed out
    if not all_jobs_complete:
        # send slack notification 
        if os.path.isfile("%s/utilities/sendMessage.sh" % python_utils.EXT_DIR):
            command='{path}/utilities/sendMessage.sh -l bad -m \"<{url}|Dynamic security scan> did not complete within {wait} minutes.  Stage will need to be re-run after the scan completes.\"'.format(path=python_utils.EXT_DIR,url=dash,wait=FULL_WAIT_TIME)
            proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate();
            python_utils.LOGGER.debug(out)

        endtime = timeit.default_timer()
        print "Script completed in " + str(endtime - python_utils.SCRIPT_START_TIME) + " seconds"
        sys.exit(2)
    else:
        if high_issue_count > 0:
            # send slack notification 
            if os.path.isfile("%s/utilities/sendMessage.sh" % python_utils.EXT_DIR):
                command='{path}/utilities/sendMessage.sh -l bad -m \"<{url}|Dynamic security scan> completed with {issues} high issues detected in the application.\"'.format(path=python_utils.EXT_DIR,url=dash, issues=high_issue_count)
                proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
                out, err = proc.communicate();
                python_utils.LOGGER.debug(out)

            endtime = timeit.default_timer()
            print "Script completed in " + str(endtime - python_utils.SCRIPT_START_TIME) + " seconds"
            sys.exit(1)

        if os.path.isfile("%s/utilities/sendMessage.sh" % python_utils.EXT_DIR):
            if med_issue_count > 0: 
                command='SLACK_COLOR=\"warning\" {path}/utilities/sendMessage.sh -l good -m \"<{url}|Dynamic security scan> completed with no major issues.\"'.format(path=python_utils.EXT_DIR,url=dash)
            else:            
                command='{path}/utilities/sendMessage.sh -l good -m \"<{url}|Dynamic security scan> completed with no major issues.\"'.format(path=python_utils.EXT_DIR,url=dash)
            proc = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate();
            python_utils.LOGGER.debug(out)
        endtime = timeit.default_timer()
        print "Script completed in " + str(endtime - python_utils.SCRIPT_START_TIME) + " seconds"
        sys.exit(0)

except Exception, e:
    python_utils.LOGGER.warning("Exception received", exc_info=e)
    endtime = timeit.default_timer()
    print "Script completed in " + str(endtime - python_utils.SCRIPT_START_TIME) + " seconds"
    sys.exit(1)

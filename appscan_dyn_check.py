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
import subprocess

APP_SECURITY_SERVICE='Application Security on Cloud'
DEFAULT_SERVICE=APP_SECURITY_SERVICE
DEFAULT_SERVICE_PLAN="free"
DEFAULT_SERVICE_NAME=DEFAULT_SERVICE
DEFAULT_SCANNAME="webscan"
DEFAULT_APPSCAN_SERVER="https://appscan.bluemix.net"

# time to sleep between checks when waiting on pending jobs, in seconds
SLEEP_TIME=15

# scan info, loaded from ENV
APPSCAN_SERVER = ""
AD_BASE_URL = None
AD_USER = None
AD_PWD = None
IDS_PROJECT_NAME = None
AD_BOUND_APP = None
# our auth token
APPSCAN_TOKEN = None
# default to not approved to spend money
COST_APPROVED = False
SCAN_TYPE = None
# some appscan defines - production scan tries harder to be
# nondestructive.  staging is more willing to submit posts, deletes, etc
APPSCAN_SCAN_TYPE_PRODUCTION = "Production"
APPSCAN_SCAN_TYPE_STAGING    = "Staging"

# check cli args, set globals appropriately
def parse_args ():
    global APPSCAN_SERVER, AD_BASE_URL, AD_USER, AD_PWD, IDS_PROJECT_NAME, SCAN_TYPE, COST_APPROVED, AD_BOUND_APP, SCAN_TYPE
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
    AD_BOUND_APP = os.environ.get('AD_BOUND_APP')
    SCAN_TYPE = os.getenv('AD_SCAN_TYPE', APPSCAN_SCAN_TYPE_PRODUCTION)
    if SCAN_TYPE.lower() == APPSCAN_SCAN_TYPE_STAGING.lower():
        SCAN_TYPE = APPSCAN_SCAN_TYPE_STAGING
    else:
        SCAN_TYPE = APPSCAN_SCAN_TYPE_PRODUCTION
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
    print "\t   SETUP_SERVICE_SPACE    : flag indicating approval to setup the service."
    print "\t                          : Service must be in your space if this flag set is not set."
    print "\t   AD_SCAN_TYPE   : \"Production\" or \"Staging\".  \"Staging\" can be a destructive scan"
    print ""



# create a template for a current scan.  this will be in the format
# "<scanname>-<type>-<version>" where scanname comes from env var 
# 'SUBMISSION_NAME', type comes from env var AD_SCAN_TYPE, and 
# version comes from env var 'APPLICATION_VERSION'
# because type of scan is not included in scan detail, we use it in naming convention
def get_scanname_template (include_version=True):
    # check the env for name of the scan, else use default
    if os.environ.get('SUBMISSION_NAME'):
        scanname = os.environ.get('SUBMISSION_NAME')
    elif IDS_PROJECT_NAME:
        scanname = IDS_PROJECT_NAME
    else:
        scanname = DEFAULT_SCANNAME

    print scanname
    print SCAN_TYPE
    # if no version, will end with a dash - this is expected (and used)
    # for matching old versions
    scanname = scanname + "-" + SCAN_TYPE + "-"
    
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

    url = "%s/api/V2/Account/BluemixLogin" % APPSCAN_SERVER
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

    url = "%s/api/v2/Scans/DynamicAnalyzer" % APPSCAN_SERVER
    body_struct = {}
    body_struct["ScanName"] = get_scanname_template()
    body_struct["StartingUrl"] = baseurl
    body_struct["ScanType"] = SCAN_TYPE
    if baseuser:
        body_struct["LoginUser"] = baseuser
    if basepwd:
        body_struct["LoginPassword"] = basepwd
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
    return res.json()

def rescan_submit (scan):
    #/api/v2/Scans/{scanId}/Executions    
    if not APPSCAN_TOKEN:
        raise Exception("Attempted submit with no valid login token")
    
    scanid = scan["Id"]
    
    url = "%s/api/v2/Scans/%s/Executions" % (APPSCAN_SERVER, str(scanid))
    xheaders = {
        'content-type': 'application/json',
        'Authorization': APPSCAN_TOKEN
    }

    if python_utils.DEBUG:
        python_utils.LOGGER.debug("Sending request \"" + str(url) + "\" with headers \"" + str(xheaders) + "\"")
    res = requests.post(url, headers=xheaders)
    if python_utils.DEBUG:
        python_utils.LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

    if res.status_code >= 300:
        raise Exception("Unable to communicate with Dynamic Analysis service (list), status code " + str(res.status_code))

    response_execution = res.json()
    scan["LatestExecution"]=response_execution
    return scan

# get appscan list of current scans
# returns the list of scan information
def appscan_list ():
    if not APPSCAN_TOKEN:
        raise Exception("Attempted submit with no valid login token")

    url = "%s/api/v2/Scans/" % APPSCAN_SERVER
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
        if scan["Technology"] == "DynamicAnalyzer":
            scanlist.append(scan)
    return scanlist


# given a state, is the job completed
def get_state_completed (state):
    return {
        "Running" : False,
        "Ready" : True,
        "Failed" : True
    }.get(state, True)

# given a state, was it completed successfully
def get_state_successful (state):
    return {
        "Running" : False,
        "Ready" : True,
        "Failed" : False
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

def refresh_appscan_info (scan):

    if not APPSCAN_TOKEN:
        raise Exception("Attempted submit with no valid login token")
    
    scanid = scan["Id"]
    
    url = "%s/api/v2/Scans/DynamicAnalyzer/%s" % (APPSCAN_SERVER, str(scanid))
    xheaders = {
        'content-type': 'application/json',
        'Authorization': APPSCAN_TOKEN
    }

    if python_utils.DEBUG:
        python_utils.LOGGER.debug("Sending request \"" + str(url) + "\" with headers \"" + str(xheaders) + "\"")
    res = requests.get(url, headers=xheaders)
    if python_utils.DEBUG:
        python_utils.LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

    if res.status_code >= 300:
        raise Exception("Unable to communicate with Dynamic Analysis service (list), status code " + str(res.status_code))

    response_scan = res.json()
    if response_scan["Id"] == scanid:
        return response_scan

    raise Exception("Job not found")

def get_appscan_xml_report (scan):

    if not APPSCAN_TOKEN:
        raise Exception("Attempted to get report with no valid login token")
    
    scanid = scan["Id"]
    
    url = "%s/api/v2/Scans/%s/Report/xml" % (APPSCAN_SERVER, str(scanid))
    xheaders = {
        'content-type': 'application/json',
        'Authorization': APPSCAN_TOKEN
    }

    if python_utils.DEBUG:
        python_utils.LOGGER.debug("Sending request \"" + str(url) + "\" with headers \"" + str(xheaders) + "\"")
    res = requests.get(url, headers=xheaders)
    if python_utils.DEBUG:
        python_utils.LOGGER.debug("received status " + str(res.status_code) + " and data " + str(res.text))

    if res.status_code >= 300:
        raise Exception("Unable to communicate with Dynamic Analysis service (xml report), status code " + str(res.status_code))
    
    #
    # Store the appscan report
    f = open( "appscan_%s.xml" % (str(scanid)),'w' )
    f.write( res.text )
    f.close()
    
    return True

# get status of a given scan
def parse_status (scan):
    if scan == None:
        raise Exception("No jobid to check status")
    return scan["LatestExecution"]["Status"]

# if the job we would run is already up (and either pending or complete),
# we just want to get state (and wait for it if needed), not create a whole
# new submission.  for the key, we use the job name, compared to the
# name template as per get_scanname_template()
def check_for_existing_scan ( ignore_older_jobs = True):
    allscans = appscan_list()
    if allscans == None:
        # no jobs, ours can't be there
        return None

    # get the name we're looking for
    scan_name = get_scanname_template( include_version = ignore_older_jobs )
    scanlist = []
    found = False
    for scan in allscans:
        if scan["Name"].startswith(scan_name):
            scanlist.append(scan)
            found = True
    if found:
        return scanlist
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
    dash = python_utils.find_service_dashboard(APP_SECURITY_SERVICE)
    for jobid in joblist:
        try:
            while True:
                scan = refresh_appscan_info(jobid)
                state = parse_status(scan)
                python_utils.LOGGER.info("Job " + scan["Id"] + " in state " + state)
                if get_state_completed(state):
                    if get_state_successful(state):
                        high_issue_count += scan["LatestExecution"]["NHighIssues"]
                        med_issue_count += scan["LatestExecution"]["NMediumIssues"]
                        python_utils.LOGGER.info("Analysis successful (" + scan["Name"] + ")")
                        #print "\tOther Message : " + msg
                        #appscan_get_result(jobid)
                        print python_utils.LABEL_GREEN + python_utils.STARS
                        print "Analysis successful for job \"" + scan["Name"] + "\""
                        print "\tHigh Severity Issues   : " + str(scan["LatestExecution"]["NHighIssues"])
                        print "\tMedium Severity Issues : " + str(scan["LatestExecution"]["NMediumIssues"])
                        print "\tLow Severity Issues    : " + str(scan["LatestExecution"]["NLowIssues"])
                        print "\tInfo Severity Issues   : " + str(scan["LatestExecution"]["NInfoIssues"])
                        
                        if os.environ.get('DRA_IS_PRESENT') == "1":
                            if python_utils.DEBUG:
                                print "DRA is PRESENT"
                            get_appscan_xml_report( scan )
                        
                        if dash != None:
                            print "See detailed results at: " + python_utils.LABEL_COLOR + " " + dash
                        print python_utils.LABEL_GREEN + python_utils.STARS + python_utils.LABEL_NO_COLOR
                    else: 
                        python_utils.LOGGER.info("Analysis unsuccessful (" + results["Name"] + ") with message \"" + results["UserMessage"] + "\"")

                    break
                else:
                    time_left = python_utils.get_remaining_wait_time()
                    if (time_left > SLEEP_TIME):
                        time.sleep(SLEEP_TIME)
                    else:
                        # ran out of time, flag that at least one job didn't complete
                        all_jobs_complete = False
                        # get what info we can on this job
                        scan = refresh_appscan_info(jobid)
                        # notify the user
                        print python_utils.LABEL_RED + python_utils.STARS
                        print "Analysis incomplete for job \"" + scan["Name"] + "\""
                        print "\t" + str(scan["LatestExecution"]["Progress"]) + "% complete"
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

    # Upload appscan.xml files to DRA
    if os.environ.get('DRA_IS_PRESENT') == "1":
        subprocess.call( "./dra.sh", shell=True )
    
    return all_jobs_complete, high_issue_count, med_issue_count


# begin main execution sequence

#TODO: Follow-up on UserAgreeToPay...COST_APPROVED 


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
#    creds = python_utils.get_credentials_for_non_binding_service(service=APP_SECURITY_SERVICE)
#    python_utils.LOGGER.info("Connecting to Dynamic Analysis service")
#    appscan_login(creds['bindingid'],creds['password'])

    #get_credentials_from_bound_app will bind the app if SETUP_SERVICE_SPACE is true
    if AD_BOUND_APP:
        creds = python_utils.get_credentials_from_bound_app(service=APP_SECURITY_SERVICE, binding_app=AD_BOUND_APP)
    else:
        creds = python_utils.get_credentials_for_non_binding_service(service=APP_SECURITY_SERVICE)
    python_utils.LOGGER.info("Connecting to Dynamic Analysis service")
    appscan_login(creds['bindingid'],creds['password'])
    # allow testing connection without full job scan and submission
    if parsed_args['loginonly']:
        python_utils.LOGGER.info("LoginOnly set, login complete, exiting")
        endtime = timeit.default_timer()
        print "Script completed in " + str(endtime - python_utils.SCRIPT_START_TIME) + " seconds"
        sys.exit(0)

    # see if we have related jobs (need this for both paths)
    joblist = check_for_existing_scan(ignore_older_jobs=False)
    # if checkstate, don't really do a scan, just check state of current outstanding ones
    if parsed_args['checkstate']:
        # for checkstate, don't wait, just check current
        python_utils.WAIT_TIME = 0
        if joblist == None:
            # no related jobs, get whole list
            joblist = appscan_list()
    else:
        # save list of old jobs
        if joblist == None:
            joblist = []
        old_joblist = joblist
        joblist = []
        #     Go through the jobs and find out for each:
        #      If it matches our AD_BASE_URL
        #      If it is rerunnable for free
        #      Because staging/production is not returend in scan detail, we use it in naming convention
        for job in old_joblist:
            updated_job_info = refresh_appscan_info(job)
            if updated_job_info:
                job = updated_job_info
            job_url = job["LatestExecution"]["StartingUrl"]
            #put free rerun end date in a format strptime can understand
            job_free_end = job["FreeRerunEndDate"].rstrip("Z")+"UTC"
            #Check against 60 seconds into the future, to avoid accidentally charging
            if job_url == AD_BASE_URL and time.strptime(job_free_end, "%Y-%m-%dT%H:%M:%S.%f%Z") > time.gmtime(time.time()+60):
                python_utils.LOGGER.debug("Found matching job "+str(job))
                joblist.append(job)
        if joblist:
            python_utils.LOGGER.info("Matching jobs found")
        else:
            python_utils.LOGGER.info("No matching jobs found")
            joblist = None
            
        # if the job we would run is already up (and either pending or complete),
        # we just want to get state (and wait for it if needed), not create a whole
        # new submission (check current version only at this point)
        if joblist == None:
            joblist = []
            python_utils.LOGGER.info("Submitting URL for analysis")
            job = appscan_submit(AD_BASE_URL, baseuser=AD_USER, basepwd=AD_PWD, oldjobs=old_joblist)
            joblist.append(job)
            python_utils.LOGGER.info("Waiting for analysis to complete")
        else:
            #Check here if status is Running, if running, just wait on it and report.  If not running, then rescan
            python_utils.LOGGER.info("Existing job found, checking status")
            for job in joblist:
                job_state = job["LatestExecution"]["Status"]
                if job_state == "Running":
                    python_utils.LOGGER.info("Existing scan is running, a new scan will not be started")
                    break
                else:
                    job = rescan_submit(job)
                    joblist = []
                    joblist.append(job)
                    break

    # check on pending jobs, waiting if appropriate
    all_jobs_complete, high_issue_count, med_issue_count = wait_for_scans(joblist)

    # prebuild common substrings
    dash = python_utils.find_service_dashboard(APP_SECURITY_SERVICE)
    # if we didn't successfully complete jobs, return that we timed out
    if not all_jobs_complete:
        # send slack notification 
        if os.path.isfile("%s/utilities/sendMessage.sh" % python_utils.EXT_DIR):
            command='{path}/utilities/sendMessage.sh -l bad -m \"<{url}|Dynamic security scan> did not complete within {wait} minutes.  Stage will need to be re-run after the scan completes.\"'.format(path=python_utils.EXT_DIR,url=dash,wait=python_utils.FULL_WAIT_TIME)
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

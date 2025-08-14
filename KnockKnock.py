#!/usr/bin/python3

import os,re,sys,json,time,logging,contextlib,subprocess,argparse,urllib3,requests
from pathlib import Path
from alive_progress import alive_bar
from argparse import RawTextHelpFormatter
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from webdriver_manager.firefox import GeckoDriverManager
from threading import Thread, Event
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

banner = r"""
  _  __                 _    _  __                 _
 | |/ /_ __   ___   ___| | _| |/ /_ __   ___   ___| | __
 | ' /| '_ \ / _ \ / __| |/ / ' /| '_ \ / _ \ / __| |/ /
 | . \| | | | (_) | (__|   <| . \| | | | (_) | (__|   <
 |_|\_\_| |_|\___/ \___|_|\_\_|\_\_| |_|\___/ \___|_|\_\\
    v1.2                                  @waffl3ss"""
print(banner)
print("\n")

parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
parser.add_argument('--teams', dest='runTeams', required=False, default=False, help="Run the Teams User Enumeration Module", action="store_true")
parser.add_argument('--onedrive', dest='runOneDrive', required=False, default=False, help="Run the One Drive Enumeration Module", action="store_true")
parser.add_argument('-l', dest='teamsLegacy', required=False, default=False, help="Write legacy skype users to a seperate file", action="store_true")
parser.add_argument('-s', dest='teamsStatus', required=False, default=False, help="Write Teams Status for users to a seperate file", action="store_true")
parser.add_argument('-i', dest='inputList', type=argparse.FileType('r'), required=True, default='', help="Input file with newline-seperated users to check")
parser.add_argument('-o', dest='outputfile', type=str, required=False, default='', help="Write output to file")
parser.add_argument('-d', dest='targetDomain', type=str, required=True, default='', help="Domain to target")
parser.add_argument('-t', dest='teamsToken', required=False, default='', help="Teams Token, either file, string, or 'proxy' for interactive Firefox")
parser.add_argument('--threads', dest='maxThreads', required=False, type=int, default=10, help="Number of threads to use in the Teams User Enumeration (default = 10)")
parser.add_argument('-v', dest='verboseMode', required=False, default=False, help="Show verbose errors", action="store_true")
args = parser.parse_args()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

if args.verboseMode:
	logger.setLevel(logging.DEBUG)
 
if not args.runTeams and not args.runOneDrive:
    logger.error("You must select one enumeration module, Teams or OneDrive... Exiting...")
    sys.exit()

if args.runTeams and args.teamsToken == '':
    logger.error("Teams Bearer Token required for Teams enumeration, Exiting...")
    sys.exit()

if args.teamsLegacy and args.outputfile == '':
    logger.error("Teams Legacy Output requires the output file option (-o). Exiting...")
    sys.exit()

if args.teamsStatus and args.outputfile == '':
    logger.error("Teams Status Output requires the output file option (-o). Exiting...")
    sys.exit()

MITMPROXY_PORT=8000

validNames = set()
legacyNames = set()
statusNames = set()
outfile = None
legOut = None
statusOut = None

def OneDriveEnumerator(targetTenant, potentialNameOD):
    global outfile
    global legOut
    global statusOut
    
    try:
        testURL = "https://" + targetTenant + "-my.sharepoint.com/personal/" + str(potentialNameOD.replace(".","_")) + "_" + str(args.targetDomain.replace(".","_")) + "/_layouts/15/onedrive.aspx"
        logger.debug("Testing: " + str(testURL))
        userRequest = requests.get(testURL, verify=False)
        if userRequest.status_code in [200, 401, 403, 302]:
            logger.info(" [+] " + str(str(potentialNameOD) + "@" + str(args.targetDomain)))
            validName = potentialNameOD.strip().lower()
            validNames.add(validName)
            outfile.write(validName + "@" + args.targetDomain + "\n")
        else:
            logger.debug(" [-] " + str(str(potentialNameOD) + "@" + str(args.targetDomain)))
            pass

    except Exception as e:
        logger.debug("[V] " + str(e))
        pass

def getPresence(mri, bearer):
    URL_PRESENCE_TEAMS = "https://presence.teams.microsoft.com/v1/presence/getpresence/"

    initHeaders = {
        "x-ms-client-version": "CLIENT_VERSION",
        "Authorization": "Bearer " + bearer,
        "Content-Type": "application/json",
    }   

    json_data = json.dumps([{"mri": mri}])
    
    try:
        response = requests.post(URL_PRESENCE_TEAMS, data=json_data, headers=initHeaders)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.debug(f"Error on response. [ERROR] - {e}")
        return None, None

    try:
        status = response.json()

        try:
            availability = status[0]['presence']['availability']
        except (KeyError, IndexError, TypeError):
            availability = None

        try:
            device_type = status[0]['presence']['deviceType']
        except (KeyError, IndexError, TypeError):
            device_type = None

        try:
            out_of_office_note = str(status[0]['presence'].get('calendarData', {}).get('outOfOfficeNote', {}).get('message'))
        except (KeyError, IndexError, TypeError):
            out_of_office_note = None
        
        return availability, device_type, out_of_office_note
    
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        logger.debug(f"Error parsing response JSON [ERROR] - {e}")
        return None, None, None


def teamsEnum(theToken, potentialUserNameTeams):
    global outfile
    global legOut
    global statusOut
    
    try:
        logger.debug(" [V] Testing user %s" % potentialUserNameTeams)

        URL_TEAMS = "https://teams.microsoft.com/api/mt/emea/beta/users/"
        CLIENT_VERSION = "27/1.0.0.2021011237"
        
        initHeaders = {
            "Host": "teams.microsoft.com",
            "Authorization": "Bearer " + theToken.strip(),
            "X-Ms-Client-Version": str(CLIENT_VERSION),
        }

        initRequest = requests.get(URL_TEAMS + str(potentialUserNameTeams) + "/externalsearchv3?includeTFLUsers=true", headers=initHeaders)
        potentialUserNameTeamsResult = potentialUserNameTeams.split("@")[0].strip().lower()
        if initRequest.status_code == 403:
            logger.info(" [+] %s" % potentialUserNameTeams.strip().lower())
            if potentialUserNameTeamsResult not in validNames:
                validNames.add(potentialUserNameTeamsResult)
                outfile.write(potentialUserNameTeamsResult + "@" + args.targetDomain + "\n")

        elif initRequest.status_code == 404:
            logger.debug(" Error with username - %s" % str(potentialUserNameTeams.strip().lower()))

        elif initRequest.status_code == 200:
            statusLevel = json.loads(initRequest.text)

            if statusLevel:
                if "skypeId" in statusLevel[0]:
                    logger.info(" [+] %s -- Legacy Skype Detected" % potentialUserNameTeams)
                    if potentialUserNameTeamsResult not in validNames:
                        validNames.add(potentialUserNameTeamsResult)
                        outfile.write(potentialUserNameTeamsResult + "@" + args.targetDomain + "\n")
                    if potentialUserNameTeamsResult not in legacyNames:
                        legacyNames.add(potentialUserNameTeamsResult)
                        legOut.write(potentialUserNameTeamsResult + "@" + args.targetDomain + "\n")
                    logger.debug(json.dumps(statusLevel, indent=2))
                else:
                    if not args.teamsStatus:
                        logger.info(" [+] %s" % potentialUserNameTeams)
                        if potentialUserNameTeamsResult not in validNames:
                            validNames.add(str(potentialUserNameTeamsResult))
                            outfile.write(potentialUserNameTeamsResult + "@" + args.targetDomain + "\n")
                        logger.debug(json.dumps(statusLevel, indent=2))

                if args.teamsStatus:
                    mriStatus = statusLevel[0].get("mri")
                    availability, device_type, out_of_office_note = getPresence(mriStatus, theToken)
                    if out_of_office_note is None:
                        logger.info(f" [+] %s -- %s -- %s" % (potentialUserNameTeams.strip(), availability, device_type))
                        status = f"{potentialUserNameTeams.strip().lower()} -- {availability} -- {device_type}"
                        if status not in statusNames:
                            statusNames.add(status)
                            statusOut.write(status + "\n")
                    if out_of_office_note is not None:
                        logger.info(" [+] %s -- %s -- %s -- %s" % (potentialUserNameTeams.strip().lower(), availability, device_type, repr(out_of_office_note)))
                        status = f"{potentialUserNameTeams.strip().lower()} -- {availability} -- {device_type} -- {repr(out_of_office_note)}"
                        if status not in statusNames:
                            statusNames.add(status)
                            statusOut.write(status + "\n")
                    if potentialUserNameTeamsResult not in validNames:
                        validNames.add(potentialUserNameTeamsResult)
                        outfile.write(potentialUserNameTeamsResult + "@" + args.targetDomain + "\n")
            else:
                logger.debug(" [-] %s" % potentialUserNameTeams.strip().lower())

        elif initRequest.status_code == 401:
            logger.error(" Error with Teams Auth Token... \n\tShutting down threads and Exiting")
            sys.exit()
        
    except Exception as e:
        logger.debug(" [V] " + str(e))
        pass      


       
def start_mitmproxy(debug, exit_event):
    mitmproxy_script = os.path.join(os.getcwd(), "mitmproxy_addon.py")

    with open(mitmproxy_script, "w") as f:
        f.write('''
from mitmproxy import http
import os

def response(flow: http.HTTPFlow):
    if "/oauth2/v2.0/token?client-request-id=" in flow.request.path:
        if flow.response and b"skype" in flow.response.content:
            try:
                token_json = flow.response.json()
                access_token = token_json.get("access_token")
                if access_token:
                    with open("token.txt", "w") as token_file:
                        token_file.write("Bearer " + access_token)
                    os._exit(0)
            except Exception as e:
                pass
''')

    def run_mitmproxy():
        cmd = [
            "mitmdump",
            "-s", mitmproxy_script,
            "--mode", "regular",
            "--listen-port", str(MITMPROXY_PORT),
            "--ssl-insecure",
            "--set", "termlog_verbosity=error"
        ]
        if not debug:
            cmd.extend([">", "/dev/null", "2>&1"])
        logger.info("Starting mitmproxy...")
        subprocess.run(cmd)
        exit_event.set()

    thread = Thread(target=run_mitmproxy)
    thread.daemon = True
    thread.start()
    time.sleep(3)

def setup_firefox_options():
    options = Options()
    options.set_preference("security.enterprise_roots.enabled", True)
    options.set_preference("network.proxy.type", 1)
    options.set_preference("network.proxy.http", "localhost")
    options.set_preference("network.proxy.http_port", MITMPROXY_PORT)
    options.set_preference("network.proxy.ssl", "localhost")
    options.set_preference("network.proxy.ssl_port", MITMPROXY_PORT)
    options.set_preference("network.cookie.cookieBehavior", 0)
    options.set_preference("dom.security.https_only_mode", False)
    options.set_preference("privacy.trackingprotection.enabled", False)
    return options

@contextlib.contextmanager
def suppress_stdout_stderr():
    with open(os.devnull, 'w') as devnull:
        with contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
            yield

def start_firefox(options):
    logging.getLogger("WDM").setLevel(logging.CRITICAL)
    with suppress_stdout_stderr():
        service = Service(GeckoDriverManager().install())
    driver = webdriver.Firefox(service=service, options=options)
    return driver

def get_tenant_name(target_domain):
    logger.debug(" [V] Method 1: SharePoint Discovery...")
    try:
        sharepoint_url = f"https://{target_domain.split('.')[0]}-my.sharepoint.com"
        response = requests.get(sharepoint_url, timeout=10, allow_redirects=False, verify=False)

        if response.status_code == 302:
            location = response.headers.get('location', '')
            logger.debug(f" [V] SharePoint redirect: {location}")

            tenant_match = re.search(r'https://([^-]+)-my\.sharepoint\.com', location)
            if tenant_match:
                tenant_name = tenant_match.group(1)
                logger.debug(f" [V] SUCCESS: Found tenant via SharePoint: {tenant_name}")
                return tenant_name
            else:
                logger.debug(" [V] FAIL: Could not extract tenant from SharePoint redirect")
        else:
            logger.debug(f" [V] FAIL: SharePoint response status: {response.status_code}")

    except Exception as e:
        logger.debug(f" [V] FAIL: SharePoint discovery failed: {e}")

    logger.debug(" [V] Method 2: Pattern Probing (backup)...")
    common_patterns = [
        target_domain.split('.')[0],
        target_domain.split('.')[0].replace('-', ''),
        target_domain.replace('.com', '').replace('.', ''),
        target_domain.replace('.', ''),
    ]

    for i, pattern in enumerate(common_patterns):
        logger.debug(f" [V] Testing pattern {i+1}: {pattern}")
        try:
            test_url = f"https://{pattern}-my.sharepoint.com"
            test_response = requests.get(test_url, timeout=5, allow_redirects=False, verify=False)

            if test_response.status_code in [302, 200, 401, 403]:
                logger.debug(f" [V] SUCCESS: Found working tenant pattern: {pattern} (HTTP {test_response.status_code})")
                return pattern
            else:
                logger.debug(f" [V] FAIL: Pattern {pattern} returned HTTP {test_response.status_code}")

        except Exception as e:
            logger.debug(f" [V] ERROR: Pattern {pattern} failed: {e}")
            continue

    fallback_tenant = target_domain.split('.')[0]
    logger.debug(f" [V] FALLBACK: Using domain-based tenant: {fallback_tenant}")
    return fallback_tenant

def getNumOfLinesInFile(f):
    numOfLines = 0
    for _ in f:
        numOfLines += 1
    f.seek(0)
    return numOfLines

def main():
    global bar
    global bar2
    global outfile
    global legOut
    global statusOut

    if args.teamsStatus:
        logger.info(" Username -- Availability -- Device Type -- Out of Office Note\n")

    #####################
    ## Setup output files
    #####################
    if args.outputfile != '':
        # Output file
        overwriteOutputFile = True
        if Path.exists(Path(args.outputfile)):
            overwriteOutFileChoice = input(" [!] Output File exists, overwrite? [Y/n] ")
            if overwriteOutFileChoice == "y" or "Y" or "":
                overwriteOutputFile = True
                Path(args.outputfile).unlink(missing_ok=True)
            else:
                overwriteOutputFile = False
        if overwriteOutputFile:
            outfile = open(args.outputfile, 'w')
        else:
            logger.info(" Not overwriting output file")

        # Teams legacy
        if args.teamsLegacy:
            legacyOutFile = "Legacy_" + str(args.outputfile)
            legacyOverwriteFile = True
            if Path.exists(Path(legacyOutFile)):
                legOverwriteChoice = input("[!] Legacy Output File exists, overwrite? [Y/n] ")
                if legOverwriteChoice == "y" or "Y" or "":
                    legacyOverwriteFile = True
                    Path(legacyOutFile).unlink(missing_ok=True)
                else:
                    legacyOverwriteFile = False
            if legacyOverwriteFile:
                legOut = open(legacyOutFile, "w")
            else:
                logger.info(" Not overwriting legacy skype users file")
        else:
            logger.info(" No legacy skype users identified")

        # Teams status
        if args.teamsStatus:
            if args.outputfile != '':
                statusOutFile = "Status_" + str(args.outputfile)
                statusOverwriteFile = True

                if Path.exists(Path(statusOutFile)):
                    statusOverwriteChoice = input(" [!] Status Output File exists, overwrite? [Y/n] ")
                    if statusOverwriteChoice == "y" or "Y" or "":
                        statusOverwriteFile = True
                        Path(statusOutFile).unlink(missing_ok=True)
                    else:
                        statusOverwriteFile = False

                if statusOverwriteFile:
                    titleLine = "Username -- Availability -- Device Type -- Out of Office Note\n"
                    statusOut = open(statusOutFile, "a+")
                    statusOut.write(titleLine)
                else:
                    logger.info(" Not overwriting status file")

    ###########
    ## OneDrive
    ###########
    if args.runOneDrive:
        try:
            logger.debug(" [V] Running OneDrive Enumeration")

            try:
                logger.debug(" [V] Discovering tenant for target domain")
                targetTenant = get_tenant_name(args.targetDomain)
                if not targetTenant:
                    logger.error(" Error retrieving tenant for target, Exiting...")
                    sys.exit()
            except Exception as e:
                logger.error(" Error retrieving tenant for target, Exiting...")
                logger.debug(" [V] " + str(e))
                sys.exit()

            logger.debug(" [V] Using target tenant %s" % targetTenant)
            logger.debug(" [V] Running OneDrive Enumeration using %i threads" % args.maxThreads)
                    
            with alive_bar(getNumOfLinesInFile(args.inputList), title="Enumerating OneDrive Users", enrich_print=False) as bar:
                with ThreadPoolExecutor(max_workers=args.maxThreads) as executor:
                    batchedFutures = set()
                    while True:
                        while len(batchedFutures) < args.maxThreads:
                            try:
                                batchedFutures.add(
                                    executor.submit(
                                        OneDriveEnumerator,
                                        targetTenant,
                                        args.inputList.readline().strip().split("@")[0]
                                        )
                                )
                            except:
                                pass

                        if len(batchedFutures) == 0:
                            break

                        for future in as_completed(batchedFutures):
                            batchedFutures.remove(future)
                            bar()
                            break

        except Exception as e:
            logger.error(" Error running OneDrive Enumeration")
            logger.debug(" " + str(e))

    ########
    ## Teams
    ########
    if args.runTeams:
        try:
            if len(args.teamsToken) < 150 and Path(args.teamsToken).is_file():
                tokenFile = open(args.teamsToken, 'r')
                theToken = str(tokenFile.read())
                if "Bearer" in theToken:
                    theToken = theToken.replace("Bearer%3D","").replace("%26Origin%3Dhttps%3A%2F%2Fteams.microsoft.com","").replace("%26origin%3Dhttps%3A%2F%2Fteams.microsoft.com","").replace("Bearer ","").strip()

            elif args.teamsToken == 'proxy':
                exit_event = Event()
                start_mitmproxy(args.verboseMode, exit_event)
                options = setup_firefox_options()
                driver = start_firefox(options)

                try:
                    logger.info("Opening Teams in Firefox...")
                    driver.get("https://teams.microsoft.com")
                    logger.info("Waiting for authorization token...")
                    exit_event.wait()
                    logger.info("Token captured to token.txt")
                except Exception as e:
                    logger.error(f"Error: {e}")
                finally:
                    logger.info("Closing Firefox and stopping mitmproxy...")
                    driver.quit()
                    subprocess.run(["pkill", "mitmdump"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    os.remove("mitmproxy_addon.py")

                    tokenFile = open("token.txt", 'r')
                    theToken = str(tokenFile.read())
                    theToken = theToken.replace("Bearer ","")

            else:
                theToken = str(args.teamsToken)
                if "Bearer" in theToken:
                    theToken = theToken.replace("Bearer%3D","").replace("%26Origin%3Dhttps%3A%2F%2Fteams.microsoft.com","").replace("%26origin%3Dhttps%3A%2F%2Fteams.microsoft.com","").replace("Bearer ","").strip()

            logger.debug(" Running Teams User Enumeration using %i threads" % args.maxThreads)
            args.inputList.seek(0)
            with alive_bar(getNumOfLinesInFile(args.inputList), title="Enumerating Teams Users", enrich_print=False) as bar2:
                with ThreadPoolExecutor(max_workers=args.maxThreads) as executor:
                    batchedFutures = set()
                    while True:
                        while len(batchedFutures) < args.maxThreads:
                            try:
                                name = args.inputList.readline().strip().split("@")[0]
                                if name not in validNames: # Skip names that OneDrive enumeration has already found
                                    batchedFutures.add(
                                        executor.submit(
                                            teamsEnum,
                                            theToken,
                                            f"{name}@{args.targetDomain}",
                                            )
                                    )
                            except:
                                pass

                        if len(batchedFutures) == 0:
                            break

                        for future in as_completed(batchedFutures):
                            batchedFutures.remove(future)
                            bar2()
                            break

        except Exception as e:
            logger.error(" Error running Teams Enumeration")
            logger.debug(" " + str(e))

    ####################
    ## Aggregate results
    ####################
    if outfile != None:
        outfile.close()
    if legOut != None:
        legOut.close()
    if statusOut != None:
        statusOut.close()

if __name__ == "__main__":
    main()

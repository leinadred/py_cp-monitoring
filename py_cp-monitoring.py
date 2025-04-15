#!/usr/bin/python3
#
# Monitoring Check Point Installation by Management Tasks
#
##################################################################################################
# Choose mode! prtg/nagios

mode = 'prtg'   # 'prtg' or 'nagios'

if not mode == 'prtg' and not mode == 'nagios':
    raise(SyntaxError)
#
##################################################################################################


import logging
import ipaddress
import argparse
from datetime import datetime
import base64
import json
import sys
from types import SimpleNamespace
from cpapi import APIClient, APIClientArgs
import base64
import shlex


now = datetime.now()

##################################################################################################
# setting default values - overridden, when given by call
# api_server  = ""
# api_port    = "443"
# api_user    = "admin" #None
# api_pwd     = ""
# api_context = None #""
# monitoring  = "" # either ica,emmclifetime,ips,licensing

# thresholds for state changing (warning/error)
# val_warning = 500
# val_error   = 21
##################################################################################################

argparser = argparse.ArgumentParser()
argparser.add_argument(
            "--host", required=True, help="The target to which the api requests are sent."
        )
argparser.add_argument(
            "--user", help="admin user to authenticate."
        )
argparser.add_argument(
            "--pwd", required=True, help="admin pwd or API Key to authenticate."
        )
argparser.add_argument(
            "--port", type=int, default=443, help="API Port Number"
        )
argparser.add_argument(
            "--context", default=None, help="API Context name"
        )
argparser.add_argument(
            "--monitoring", default='ica', help="aspect to monitor", choices=["ica","emmclifetime", "ips", "licensing"]
        )
argparser.add_argument(
            "--warning", type=int, default=28, help="threshold for warning state"
        )
argparser.add_argument(
            "--error", type=int, default=14, help="threshold for error state"
        )

argparser.add_argument(
            "--timeout", type=int, default=4, help="The timeout in seconds."
        )

        # is a terminal?
if sys.stdin.isatty():
    print("Terminal detected")
    args = argparser.parse_args()
else:
    pipestring = sys.stdin.read().rstrip()
    args = argparser.parse_args(shlex.split(pipestring))
    
try:
    api_server  = args.host
except NameError:
    pass
try:
    api_user    = args.user
except NameError:
    api_user = None
try:
    api_pwd     = args.pwd
except NameError:
    pass
try:
    api_port    = args.port
except NameError:
    pass
try:
    api_context = args.context
except NameError:
    api_context = None
try:
    monitoring  = args.monitoring
except NameError:
    pass
try:
    val_error   = args.error
except NameError:
    pass
try:
    val_warning = args.error
except NameError:
    pass


def fun_error(err):
    """report error to prtg"""
    print(json.dumps(
        {
            "version": 2,
            "status": "error",
            "channels": [],
            "message": """Execution error: {err}""",
        }
    ))
    sys.exit(err)
def fun_monica(connectedto):
    all = {}
     # First - ICA Certificate expiration
    if not api_context:
        try:
            #ica_expiry = client.api_call('run-script',{'script-name' : 'ica-mgmt', 'script' : "echo | cpopenssl pkcs12 -in $FWDIR/conf/InternalCA.p12 -nokeys -nomacver -passin pass: 2>/dev/null | cpopenssl x509 -noout -enddate | awk '{print $1,$2,$4}' | sed 's/notAfter=//'", 'targets': connectedto}).data['tasks'][0]['task-details'][0]['statusDescription'].strip("notAfter=")
            ica_expiry = base64.b64decode(client.api_call('run-script',{'script-name' : 'ica-cert-mon', 'script' : """echo | cpopenssl pkcs12 -in $FWDIR/conf/InternalCA.p12 -nokeys -nomacver -passin pass: 2>/dev/null | cpopenssl x509 -noout -subject -enddate| awk '{printf "%s"",",$0}END{print ""}' | sed 's/subject=O = //'| sed 's/notAfter=//'""", 'targets': connectedto}).data['tasks'][0]['task-details'][0]['responseMessage']).decode("ascii")
            if ica_expiry[-1] == ",": ica_expiry = ica_expiry[:-1]
        except:
            fun_error(Exception)
        else:
           ica_expiry = ica_expiry.replace(", ",",")
           all[ica_expiry.split(",")[0]] = {"ICA expiry" : (datetime.strptime(ica_expiry.split(",")[1], '%b %d %H:%M:%S %Y %Z') - now).days}
    else:
        try:
            ica_expiry = base64.b64decode(client.api_call('run-script',{'script-name' : 'ica-cert-mon', 'script' : """source /etc/profile.d/CP.sh; mdsenv {0}; echo | cpopenssl pkcs12 -in $FWDIR/conf/InternalCA.p12 -nokeys -nomacver -passin pass: 2>/dev/null | cpopenssl x509 -noout -subject -enddate| awk '{printf "%s"",",$0}END{print ""}' | sed 's/subject=O = //'| sed 's/notAfter=//'""".format(api_context), 'targets': connectedto}).data['tasks'][0]['task-details'][0]['responseMessage']).decode("ascii")
            if ica_expiry[-1] == ",": ica_expiry = ica_expiry[:-1]
        except:
            fun_error(Exception)

    # possible result:
    # all == {"MGM-Name": {"ICA expiry": "321"}}
    
    # Next - get managed devices by SIC certificate
    cert_expiry = base64.b64decode(client.api_call('run-script',{'script-name' : 'devices-cert-mon', 'script' : """cpca_client lscert -stat Valid | awk '!/^Comment/' | awk 'NR > 3 {{print}}' | awk '{{ printf "%s", $0; if (NR % 4 == 0) print ""; else printf " " }}' | awk '{{if ($9 ~ /SIC/) print $3,$9,$12,$25,$24,$27,$26; else if ($11 ~ /IKE/) print $3,$11,$14,$27,$26,$29,$28}}' | awk -F '[, ]' '{{if ($3 ~ /SIC/) print $1,$3,$4,$5,$6,$7,$8; else if ($2 ~ /IKE/) print $1,$2,$3,$4,$5,$6,$7}}' | sort -k6,6n -k5,5M -k4,4n -k7.1,7.7 | awk '{{print $1","$2","$4,$5,$6";"}}' | sed 's/CN=//' | sort $1""", 'targets': connectedto}).data['tasks'][0]['task-details'][0]['responseMessage']).decode("ascii")

    for dev in cert_expiry[:-2].replace("\n","").split(";"):
        try:
            dev = dev.replace(", ",",")
            if dev.startswith(","): dev = dev[1:]
            if dev.split(",")[0].lstrip() not in all:
                all[dev.split(",")[0].lstrip()] = {}
            all[dev.split(",")[0].lstrip()][dev.split(",")[1].lstrip()] = (datetime.strptime(dev.split(",")[2].lstrip(), '%d %b %Y') - now).days
        except:
            fun_error(Exception)
    return(all)

def fun_resica(result):
    if mode == "prtg":
        final = {
            "version": 2,
            "status": "ok",
            "channels": [],
            "message": "",
        }
        icacount = 10
        subcount = 100
        state = "ok"
        message = f"Monitoring ICA Certificates on {connectedto}\n"
        for item in result.keys():
            for sub in list(result[item].keys()):
                if "ICA" in sub:
                    icacount+=1
                    final["channels"].append({
                    "id": icacount,
                    "name": f"Internal CA on {str(item)}",
                    "type" : "integer",
                    "kind" : "custom",
                    "display_unit": "days",
                    "value": result[item][sub]
                })
                else:       
                    for sub in list(result[item].keys()):
                        try:
                            nextcert
                        except NameError:
                            nextcert=int(result[item][sub])
                        except:
                            fun_error(Exception)
                        if int(result[item][sub]) < nextcert:
                            nextcert = int(result[item][sub])                            
                            final["channels"].append({
                                "id": 101,
                                "name": "Next certificate is due in:",
                                "type" : "integer",
                                "kind" : "custom",
                                "display_unit": "days",
                                "value": nextcert
                            })
                    pass
                if int(result[item][sub]) < val_error:
                    if state == "ok" or "warning":
                        state = "error"
                    if int(result[item][sub]) == 1:
                        message += f"{sub} certificate of {item} expires in the next 24 hours!\n"
                    else:
                        message += f"{sub} certificate of {item} expires in the next {str(result[item][sub])} days!\n"
                elif int(result[item][sub]) < val_warning and int(result[item][sub]) > val_error:
                    if state == "ok":
                        state = "warning"
                    message += f"{sub} certificate of {item} expires in the next {str(result[item][sub])} days!\n"
                elif int(result[item][sub]) > val_warning:
                    pass
                else:
                    state = "unknown"
                    message += f"Something went wrong while getting scripts result (for {item}:{sub}). See debug log!\n"

        final["status"] = state
        final["message"] = message
        # For getting final result while debugging set breakpoint here
        final = final
    print(json.dumps(final))
    sys.exit(0)
def fun_monips(connectedto):
    ips_state = client.api_call('show-ips-status')
    if not ips_state.success:
        fun_error("Failure fetching IPS status")
    else: 
        return(ips_state.data)

def fun_resips(ips_state):
    try:
        days_from_update = round((now.timestamp()-int(ips_state['last-updated']['posix'])/1000)/86400)
        hours_from_update = round((now.timestamp()-(int(ips_state['last-updated']['posix'])/1000))/3600)
    except:
        final = {
                    "version": 2,
                    "status": "error",
                    "message": f"ERROR with dates given by API! Enable and check Debug log",
                }
        print(json.dumps(final))
        sys.exit(1)
        

    if mode == "prtg":
        final = {
            "version": 2,
            "status": "ok",
            "channels": [],
            "message": "",
        }

        final["channels"].append({
        "id": 11,
        "name": f"time since last IPS update",
        "type" : "integer",
        "kind" : "custom",
        "display_unit": "hours",
        "value": hours_from_update
        })

        final["channels"].append({
        "id": 12,
        "name": f"update available",
        "type" : "integer",
        "kind" : "custom",
        "display_unit": "hours",
        "value": hours_from_update
        })
        if val_error < val_warning:
            final = {
                "version": 2,
                "status": "unknown",
                "message": f"Error in Call. Warning value {val_warning} is greater than {val_error} - please set them correctly",
            }
        if ips_state["update-available"] == False:
            final = {
                "version": 2,
                "status": "ok",
                "message": f"No IPS update found - last updated {hours_from_update} hours ago (version: {ips_state['installed-version']}).",
                }
        elif ips_state["update-available"] == True and days_from_update > val_warning:
            final = {
                "version": 2,
                "status": "warning",
                "message": f"No IPS update found - last updated {hours_from_update} hours ago",
            }
        elif ips_state["update-available"] == True and days_from_update > val_error:
            final = {
                "version": 2,
                "status": "error",
                "message": f"No IPS update found - last updated {hours_from_update} hours ago",
            }
        elif ips_state["update-available"] == True and days_from_update < val_warning:
            final = {
                "version": 2,
                "status": "ok",
                "message": f"IPS update found - last updated {hours_from_update} hours ago (installed version: {ips_state['installed-version']} vs. latest version:{ips_state['latest-version']}).",
                }

        else:
            final = {
                "version": 2,
                "status": "unknown",
                "message": f"Error occured while fetching IPS update state - see debug log",
            }
        if ips_state["update-available"] == False and days_from_update > val_warning:
                final = {
                    "version": 2,
                    "status": "warning",
                    "message": f"No IPS update found - but last updated {days_from_update} days ago - check connectivity",
                }
            
    print(json.dumps(final))
    sys.exit(0)


if __name__ == "__main__":
    if args.context is None:
        client_args = APIClientArgs(server=api_server, unsafe="True")
    else:
        client_args = APIClientArgs(
            server=api_server, context=api_context, unsafe="True"
        )
    with APIClient(client_args) as client:
        if client.check_fingerprint() is False:
            fun_error("Please troubleshoot/debug script! Fetching Fingerprint failed!")
        if api_user and api_pwd:
            try:
                login_res = client.login(api_user, api_pwd)
            except:
                fun_error(f"""Connection failed! Error: {Exception.strerror}!""")
            if not login_res.success:
                fun_error("Login not possible")
            else:
                logging.debug("OK! Logged on")
        elif api_pwd:
            try:
                login_res = client.login_with_api_key(api_pwd)
            except:
                fun_error(f"""Connection failed! Error: {Exception.strerror}!""")
            if not login_res.success:
                fun_error("Login not possible")
            else:
                logging.debug("OK! Logged on")
        else:
            fun_error("no Login informations provided")
        connectedto = client.api_call("show-session").data["connected-server"]["name"]
        match monitoring:
            case "ica":
                fun_resica(fun_monica(connectedto))
    # Future use
    #        case "emmclifetime":
    #            
            case "ips":
                fun_resips(fun_monips(connectedto))
    
            case _:
                fun_error("no monitoring function given.")
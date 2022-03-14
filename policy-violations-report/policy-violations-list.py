
# this script fetches all policy violations in Nexus IQ and writes them to a CSV file
# usage: python3 policy-violations-list.py [iq-url] [iq-user] [iq-passwd] [listmode]
# listmode =
#   violations
#   by-component
#   by-application

import requests
import json
import csv
import sys

iqurl = sys.argv[1]
iquser = sys.argv[2]
iqpwd = sys.argv[3]

securityPolicyList = []
securityPolicyList.append("Security-Critical")
securityPolicyList.append("Security-High")
securityPolicyList.append("Security-Medium")
securityPolicyList.append("Security-Malicious")
securityPolicyList.append("Security-Namespace Conflict")
securityPolicyList.append("Integrity-Rating")

licensePolicyList = []
licensePolicyList.append("License-Banned")
licensePolicyList.append("License-None")
licensePolicyList.append("License-Copyleft")

iqapi = 'api/v2'


def getNexusIqData(end_point):
    url = "{}/{}/{}" . format(iqurl, iqapi, end_point)

    req = requests.get(url, auth=(iquser, iqpwd), verify=False)

    if req.status_code == 200:
        res = req.json()
    else:
        res = "Error fetching data"

    return res


def getPolicyIds(data):
    policyIds = ""
    policies = data['policies']

    for policy in policies:
        name = policy["name"]
        id = policy["id"]

        if name in securityPolicyList or name in licensePolicyList:
            policyIds += "p=" + id + "&"

    result = policyIds.rstrip('&')

    return result


def getCVE(reasons):
    cves = []
    cveList = ""

    for reason in reasons:
        reference = reason["reference"]

        if type(reference) is dict:
            cve = reference["value"]

            if not cve in cves:
                cves.append(cve)

    for c in cves:
        cveList += c+":"

    cveList = cveList[:-1]

    return(cveList)


def getLicense(reasons):
    licenses = []
    licenseList  = ""

    for reason in reasons:
        licenseString = reason["reason"]

        fstart = licenseString.find('(')
        fend = licenseString.find(')')

        license = licenseString[fstart:fend]
        license = license[2:-1]

        if not license in licenses:
            licenses.append(license)

    for l in licenses:
        licenseList += l+":"

    licenseList = licenseList[:-1]

    return(licenseList)


def writePolicyViolationsToCsv(policyViolations):
    applicationViolations = policyViolations['applicationViolations']

    with open("policyViolations.csv", 'w') as fd:
            writer = csv.writer(fd)

            line = []
            line.append("PolicyName")
            line.append("Reason")
            line.append("ApplicationName")
            line.append("OpenTime")
            line.append("Component")
            line.append("Stage")

            writer.writerow(line)

            for applicationViolation in applicationViolations:
                applicationPublicId = applicationViolation["application"]["publicId"]

                policyViolations = applicationViolation["policyViolations"]
                for policyViolation in policyViolations:
                    stage = policyViolation["stageId"]
                    openTime = policyViolation["openTime"]
                    policyName = policyViolation["policyName"]
                    packageUrl = policyViolation["component"]["packageUrl"]

                    constraintViolations = policyViolation["constraintViolations"]

                    for constraintViolation in constraintViolations:
                        reason = ""

                        reasons = constraintViolation["reasons"]

                        if policyName == "Integrity-Rating":
                            reason = "Integrity-Rating"
                        elif policyName in securityPolicyList:
                            reason = getCVE(reasons)
                        elif policyName in licensePolicyList:
                            reason = getLicense(reasons)
                        else:
                            reason = ""

                        line = []
                        line.append(policyName)
                        line.append(reason)
                        line.append(applicationPublicId)
                        line.append(openTime)
                        line.append(packageUrl)
                        line.append(stage)

                        writer.writerow(line)

    fd.close()

    return

def main():

    policies = getNexusIqData('policies')

    with open("policies.json", 'w') as fd:
        json.dump(policies, fd, indent=2)

    policyIds = getPolicyIds(policies)

    policyViolations = getNexusIqData("policyViolations?" + policyIds)

    with open("policyViolations.json", 'w') as fd:
        json.dump(policyViolations, fd, indent=2)

    writePolicyViolationsToCsv(policyViolations)






if __name__ == '__main__':
    main()

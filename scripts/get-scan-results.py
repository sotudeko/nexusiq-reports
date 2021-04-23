import json
import requests
import os
import os.path
import sys
import csv
import shutil


iqUrl = "http://localhost:8070"
iqUser = "admin"
iqPwd = "admin123"


def getApplicationInternalId(applicationName):
    applicationUrl = "{}/{}?publicId={}".format(iqUrl, "api/v2/applications", applicationName)
    req = requests.get(applicationUrl, auth=(iqUser, iqPwd), verify=False)

    if req.status_code != 200:
        return

    data = req.json()

    applicationData = data["applications"]
    applicationInternalId = applicationData[0]["id"]

    return applicationInternalId


def getComponentRemediation(applicationInternalId, purl, stageId):
    # remediationUrl = "{}/{}/{}".format(iqUrl, "api/v2/components/remediation/application", applicationInternalId, stageId)
    remediationUrl = "{}/{}/{}?stageId={}".format(iqUrl, "api/v2/components/remediation/application", applicationInternalId, stageId)

    payload = {}
    payload["packageUrl"] = purl
    header = {"content-type": "application/json"}
    req = requests.post(remediationUrl, auth=(iqUser, iqPwd), verify=False, data=json.dumps(payload), headers=header)

    if req.status_code != 200:
        return

    data = req.json()

    return data


def getPurl(format, componentName):
    purl = ""
    prefix = "pkg:" + format + "/"

    if format == "maven":
        purl = prefix + componentName + "?type=jar"

    if format == "npm":
        purl = prefix + componentName

    if format == "a-name":
        purl = prefix + componentName

    if format == "nuget":
        purl = prefix + componentName

    return purl


def getCoordinate(componentIdentifier):
    coordinate = ""
    format = componentIdentifier["format"]
    coordinates = componentIdentifier["coordinates"]
    nextNoViolationsVersion = coordinates["version"]

    if format == "maven":
        coordinate = coordinates["groupId"] + "/" + coordinates["artifactId"] + "@" + coordinates["version"]

    if format == "npm" or format == "nuget":
        coordinate = coordinates["packageId"] + "@" + coordinates["version"]

    if format == "a-name":
        coordinate = coordinates["name"] + "@" + coordinates["version"]

    return nextNoViolationsVersion


def getScanResults(appdir):

    resultfile = appdir + "/result.json"
    csvfile = appdir + ".csv"

    if not os.path.isfile(resultfile):
        print ("file does not exist: " + resultfile)
        return

    rfd = open(resultfile)
    data = json.load(rfd)
    rfd.close()

    applicationId = data["applicationId"]
    applicationInternalId = getApplicationInternalId(applicationId)

    reportDataUrl = data["reportDataUrl"]
    result = data["policyEvaluationResult"]["alerts"]
    affectedComponentCount = data["policyEvaluationResult"]["affectedComponentCount"]
    criticalComponentCount= data["policyEvaluationResult"]["criticalComponentCount"]
    severeComponentCount = data["policyEvaluationResult"]["severeComponentCount"]
    moderateComponentCount = data["policyEvaluationResult"]["moderateComponentCount"]
    criticalPolicyViolationCount = data["policyEvaluationResult"]["criticalPolicyViolationCount"]
    severePolicyViolationCount = data["policyEvaluationResult"]["severePolicyViolationCount"]
    moderatePolicyViolationCount = data["policyEvaluationResult"]["moderatePolicyViolationCount"]
    grandfatheredPolicyViolationCount = data["policyEvaluationResult"]["grandfatheredPolicyViolationCount"]
    totalComponentCount = data["policyEvaluationResult"]["totalComponentCount"]

    with open(csvfile, 'w') as wfd:
        wfd.write("Component Name,Next No Violations Version,Vulnerability Id,Threat Level,Policy Name\n")

        for r in result:
            policyName = r["trigger"]["policyName"]
            threatLevel = r["trigger"]["threatLevel"]
            componentName = ""
            format = ""
            cve = ""

            if threatLevel > 6:

                for componentFact in r["trigger"]["componentFacts"]:
                    format = componentFact["componentIdentifier"]["format"]

                    if format == "npm" or format == "nuget":
                        componentName = componentFact["componentIdentifier"]["coordinates"]["packageId"] + "@" + \
                                        componentFact["componentIdentifier"]["coordinates"]["version"]
                    elif format == "a-name":
                            componentName = componentFact["componentIdentifier"]["coordinates"]["name"] + "@" + \
                                            componentFact["componentIdentifier"]["coordinates"]["version"]
                    elif format == "maven":
                        componentName = componentFact["componentIdentifier"]["coordinates"]["groupId"] + "/" + \
                                        componentFact["componentIdentifier"]["coordinates"]["artifactId"] + "@" + \
                                        componentFact["componentIdentifier"]["coordinates"]["version"]

                    purl = getPurl(format, componentName)
                    remediationData = getComponentRemediation(applicationInternalId, purl, "build")
                    nextNoViolationsVersion = ""

                    if remediationData:
                        versionChanges = remediationData["remediation"]["versionChanges"]

                        for vc in versionChanges:
                            type = vc["type"]
                            if type == "next-no-violations":
                                nextNoViolationsVersion = getCoordinate(vc["data"]["component"]["componentIdentifier"])

                    for constraintfact in componentFact["constraintFacts"]:
                        for v in constraintfact["conditionFacts"]:
                            reference = v["reference"]
                            if reference:
                                cve = v["reference"]["value"]
                                cve = cve + ","
                        cve = cve[:-1]

                    if cve:
                        line = componentName + "," + nextNoViolationsVersion + "," + cve + "," + str(threatLevel) + "," + policyName + "\n"
                        wfd.write(line)
    wfd.close()
    print("csv file: " + csvfile)

    return


def main():
    appdirs = []
    appdirs.append("tut-spring-boot-kotlin")
    appdirs.append("shopizer")
    appdirs.append("angularElementsDemo")

    for ad in appdirs:
        getScanResults(ad)

if __name__ == '__main__':
    main()



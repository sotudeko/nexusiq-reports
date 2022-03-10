# loads the security_override.csv and license_override.csv files
# read the app report urls file app_reportsurls.csv 
# checks if application has secruty or license override and if so gets the policy violation information
# writes the policy info to json file for each application
# for each of the components, if it is a-name and policy threat 7+ and has security or license override, writes it to file - overrides_violations.csv
# data written
#policyThreatCategory.lower() + "," + applicationName + "," + applicationId + "," + packageUrl + "," + componentHash + "," + policyName + "," + \
                       #policyId + "," + policyThreatCategory + "," + str(policyThreatLevel) + "," + policyViolationId + "," + \
                       #str(waived) + "," + cve + "," + severity + "\n"
import sys
import os
import os.path
import csv
from applib import nexusiq, fileIO, util

iqHost = sys.argv[1]
iqUser = sys.argv[2]
iqPwd = sys.argv[3]

iq = nexusiq.NexusIQData(iqHost, iqUser, iqPwd)

outputDir = fileIO.outputDir
workdir = fileIO.violationsWorkdir

appReportsUrlsDb = fileIO.readAppsReportsUrlsFile()
securityOverridesDb = fileIO.readSecurityOverridesFile()
# licenseOverridesDb = fileIO.readLicenseOverridesFile()

appReportsUrlsCsvFile = fileIO.appReportsUrlsCsvFile
overrideViolationsCsvFile = fileIO.overrideViolationsCsvFile

def getAppReportUrl(reportApplicationId):
  reportUrl = ""

  for row in appReportsUrlsDb:
    applicationId = row[1]
    url = row[2]

    if reportApplicationId == applicationId:
      reportUrl = url
      break

  return reportUrl


def componentHasSecurityOverride(applicationId, packageUrl):
  exists = False

  for o in securityOverridesDb:
    overrideApplicationId = o[1]
    overridePackageUrl = o[4]

    if overrideApplicationId == applicationId and overridePackageUrl == packageUrl:
      exists = True
      break

  return exists


def componentHasLicenseOverride(applicationId, packageUrl):
  exists = False

  for o in licenseOverridesDb:
    overrideApplicationId = o[1]
    overridePackageUrl = o[2]

    if overrideApplicationId == applicationId and overridePackageUrl == packageUrl:
      exists = True
      break

  return exists


def getVulnerabilityDetails(reason):
  cve = "no-cve"
  severity = "no-severity"

  info = reason.split(' ')

  if len(info) == 11:
    cve = info[3]
    severity = info[10]

  # remove close bracket at the end of severity
  severity = severity[:-1]

  return cve, severity


def getLicenseDetails(reason):
  info = reason.split(' ')
  return info[4], info[8]


def getViolationInfoForOverride(url, findPackageUrl, findCve, overrideStatus, comment):

  policyReportDataUrl = url.replace('/raw', '/policy')
  statusCode, policyReportData = iq.getData('/' + policyReportDataUrl)

  if statusCode == 200:
    applicationId = policyReportData["application"]["id"]
    applicationName = policyReportData["application"]["publicId"]
    components = policyReportData["components"]

    fn = workdir + "/" + applicationName + ".json"
    fileIO.writeJsonFile(fn, policyReportData)
    print(fn)

    for component in components:
        componentHash = component["hash"]
        packageUrl = component["packageUrl"]

        if not packageUrl:
          packageUrl = "none"

        if not findPackageUrl == packageUrl:
          continue
        
        if not util.isAname(packageUrl):
          continue

        policyName = ""
        waived = ""
        reason = ""

        violations = component['violations']

        for violation in violations:
          policyThreatLevel = violation['policyThreatLevel']

          if policyThreatLevel >= 7:
            policyName = violation['policyName']
            policyId = violation['policyId']
            waived = violation['waived']
            policyThreatCategory = violation['policyThreatCategory']
            policyViolationId = violation['policyViolationId']

            if policyThreatCategory == "QUALITY":
              continue

            line = ""
            cve = ""
            severity = ""

            if  policyThreatCategory == "SECURITY": 
              constraints = violation['constraints']
              for constraint in constraints:
                conditions = constraint['conditions']

                for condition in conditions:
                  reason = condition['conditionReason']
                  cve, severity = getVulnerabilityDetails(reason)

                  # remove close bracket at the end
                  # severity = severity[:-1]

                  if not findCve == cve:
                    continue

                  with open(overrideViolationsCsvFile, 'a') as fd:

                    line = policyThreatCategory.lower() + "," + applicationName + "," + applicationId + "," + packageUrl + "," + componentHash + "," + policyName + "," + \
                          policyId + "," + str(policyThreatLevel) + "," + policyViolationId + "," + \
                          str(waived) + "," + cve + "," + severity + "," + overrideStatus + "," + comment + "\n"

                    fd.write(line)

  return


def main():

  with open(overrideViolationsCsvFile, 'w') as fd:
    fd.write('PolicyCategory,ApplicationPublicId,ApplicationId,PackageUrl,ComponentHash,PolicyName,PolicyId,PolicyThreatLevel,PolicyViolationId,Waived,CVE,Severity,OverrideStatus,Comment\n')
    fd.close()

  for o in securityOverridesDb:
    applicationName = o[0]
    applicationId = o[1]
    overrideStatus = o[2]
    comment = o[3]
    packageUrl = o[4]
    componentHash = o[5]
    cve = o[6]
    url = getAppReportUrl(applicationId)
    getViolationInfoForOverride(url, packageUrl, cve, overrideStatus, comment)


  # for o in licenseOverridesDb:
  #   applicationName = o[0]
  #   applicationId = o[1]
  #   packageUrl = o[2]
  #   status = o[3]
  #   overriddenLicense = o[4]
  #   url = getAppReportUrl(applicationId)
  #   getViolationInfoForOverride("LICENSE", url, packageUrl, "", status, overriddenLicense)

  print(overrideViolationsCsvFile)


if __name__ == '__main__':
  main()

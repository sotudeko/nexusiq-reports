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

securityOverridesDb = fileIO.readSecurityOverridesFile()
licenseOverridesDb = fileIO.readSecurityOverridesFile()

appReportsUrlsCsvFile = fileIO.appReportsUrlsCsvFile

overrideViolationsCsvFile = fileIO.overrideViolationsCsvFile


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


# def applicationHasSecurityOverride(applicationId):
#   exists = False

#   for o in securityOverridesDb:
#     overrideApplicationId = o[1]

#     if overrideApplicationId == applicationId:
#       exists = True
#       break

#   return exists

def applicationHasOverride(overridesDb, applicationId):
  exists = False

  for o in overridesDb:
    overrideApplicationId = o[1]

    if overrideApplicationId == applicationId:
      exists = True
      break

  return exists


# def componentHasSecurityOverride(applicationId, packageUrl):
#   exists = False

#   for o in securityOverridesDb:
#     overrideApplicationId = o[1]
#     overridePackageUrl = o[4]

#     if overrideApplicationId == applicationId and overridePackageUrl == packageUrl:
#       exists = True
#       break

  return exists

def componentHasOverride(overrideDb, applicationId, packageUrl):
  exists = False

  for o in overrideDb:
    overrideApplicationId = o[1]
    overridePackageUrl = o[4]

    if overrideApplicationId == applicationId and overridePackageUrl == packageUrl:
      exists = True
      break

  return exists


def getPolicyViolations():

  with open(overrideViolationsCsvFile, 'w') as fd:
    fd.write('PolicyCategory,ApplicationPublicId,ApplicationId,PackageUrl,ComponentHash,PolicyName,PolicyId,PolicyThreatLevel,PolicyViolationId,Waived,CVE,Severity\n')
    fd.close()

  

  with open(appReportsUrlsCsvFile) as csvfile:
    r = csv.reader(csvfile, delimiter=',')
    for row in r:
      applicationId = row[1]
      url = row[2]

      if not applicationHasOverride(securityOverridesDb, applicationId) and not applicationHasOverride(licenseOverridesDb, applicationId):
        continue

      policyReportDataUrl = url.replace('/raw', '/policy')
      statusCode, policyReportData = iq.getData('/' + policyReportDataUrl)

      if statusCode == 200:
        applicationId = policyReportData["application"]["id"]
        applicationName = policyReportData["application"]["publicId"]
        components = policyReportData["components"]

        fn = workdir + "/" + applicationName + ".json"
        fileIO.writeJsonFile(fn, policyReportData)
        print(fn)
        
        with open(overrideViolationsCsvFile, 'a') as fd:
          for component in components:
            componentHash = component["hash"]
            packageUrl = component["packageUrl"]

            if not packageUrl:
              packageUrl = "none"

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

                line = ""
                cve = ""
                severity = ""

                if policyThreatCategory == "SECURITY":
                  if not componentHasOverride(securityOverridesDb, applicationId, packageUrl):
                    continue

                  constraints = violation['constraints']
                  for constraint in constraints:
                    conditions = constraint['conditions']

                    for condition in conditions:
                      reason = condition['conditionReason']
                      cve, severity = getVulnerabilityDetails(reason)

                      # remove close bracket at the end
                      # severity = severity[:-1]

                if policyThreatCategory == "LICENSE":
                  if not componentHasOverride(licenseOverridesDb, applicationId, packageUrl):
                    continue

                  constraints = violation['constraints']
                  for constraint in constraints:
                    conditions = constraint['conditions']

                    for condition in conditions:
                      reason = condition['conditionReason']
                      cve, severity = getLicenseDetails(reason)

                if not policyThreatCategory == "QUALITY":
                  line = policyThreatCategory.lower() + "," + applicationName + "," + applicationId + "," + packageUrl + "," + componentHash + "," + policyName + "," + \
                       policyId + "," + str(policyThreatLevel) + "," + policyViolationId + "," + \
                       str(waived) + "," + cve + "," + severity + "\n"

                fd.write(line)

  print(overrideViolationsCsvFile)
  return


def main():

  getPolicyViolations()


if __name__ == '__main__':
  main()

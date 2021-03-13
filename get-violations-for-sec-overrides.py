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

overridesDb = fileIO.readOverridesFile()

appReportsJsonFile = '{}/{}'.format(outputDir, 'app_reports.json')
appReportsUrlsCsvFile = '{}/{}'.format(outputDir, 'app_reportsurls.csv')
appPolicyViolationsJsonFile = '{}/{}'.format(outputDir, 'violations_for_sec_overrides.json')
appPolicyViolationsCsvFile = '{}/{}'.format(outputDir, 'violations_for_sec_overrides.csv')


def applicationHasOverride(applicationId):
  exists = False

  for o in overridesDb:
    overrideApplicationId = o[1]

    if overrideApplicationId == applicationId:
      exists = True
      break

  return exists


def componentHasOverride(applicationId, packageUrl):
  exists = False

  for o in overridesDb:
    overrideApplicationId = o[1]
    overridePackageUrl = o[4]

    if overrideApplicationId == applicationId and overridePackageUrl == packageUrl:
      exists = True
      break

  return exists


def getVulnerabilityDetails(reason):
  info = reason.split(' ')
  return info[3], info[10]


def getPolicyViolations():

  with open(appPolicyViolationsCsvFile, 'w') as fd:
    fd.write('ApplicationPublicId,ApplicationId,PackageUrl,ComponentHash,PolicyName,PolicyId,PolicyThreatCategory,PolicyThreatLevel,PolicyViolationId,Waived,CVE,Severity\n')
    fd.close()

  # read the app report urls file  and get the policy violations for each application
  with open(appReportsUrlsCsvFile) as csvfile:
    r = csv.reader(csvfile, delimiter=',')
    for row in r:
      applicationId = row[1]
      url = row[2]

      if not applicationHasOverride(applicationId):
        continue

      # we want the policy violations (change raw to policy endpoint)
      policyReportDataUrl = url.replace('/raw', '/policy')
      statusCode, policyReportData = iq.getData('/' + policyReportDataUrl)

      if statusCode == 200:
        applicationId = policyReportData["application"]["id"]
        applicationName = policyReportData["application"]["publicId"]
        components = policyReportData["components"]

        #  write the json data
        fn = workdir + "/" + applicationName + ".json"
        fileIO.writeJsonFile(fn, policyReportData)
        print(fn)
        
        #  write to csv file
        with open(appPolicyViolationsCsvFile, 'a') as fd:
          for component in components:
            componentHash = component["hash"]
            packageUrl = component["packageUrl"]

            if not packageUrl:
              packageUrl = "none"

            # write only if it is format we need (ie. a-name)
            if not util.overrideFormat(packageUrl):
              continue

            #  write only if this component has an override
            if not componentHasOverride(applicationId, packageUrl):
              continue

            policyName = ""
            waived = ""
            reason = ""

            violations = component['violations']

            for violation in violations:
              policyThreatLevel = violation['policyThreatLevel']

              # Only write if above threat level threshold
              if policyThreatLevel >= 7:
                policyName = violation['policyName']
                policyId = violation['policyId']
                waived = violation['waived']
                policyThreatCategory = violation['policyThreatCategory']
                policyViolationId = violation['policyViolationId']

                constraints = violation['constraints']
                for constraint in constraints:
                  conditions = constraint['conditions']

                  for condition in conditions:
                    reason = condition['conditionReason']
                    cve, severity = getVulnerabilityDetails(reason)

                    # remove close bracket at the end
                    severity = severity[:-1]

                line = applicationName + "," + applicationId + "," + packageUrl + "," + componentHash + "," + policyName + "," + \
                       policyId + "," + policyThreatCategory + "," + str(policyThreatLevel) + "," + policyViolationId + "," + \
                       str(waived) + "," + cve + "," + severity + "\n"

                # write to file
                fd.write(line)

  print(appPolicyViolationsCsvFile)
  return


def main():

  getPolicyViolations()


if __name__ == '__main__':
  main()

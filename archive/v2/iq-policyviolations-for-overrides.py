import sys
import os
import os.path
import csv
from applib import nexusiq, fileIO, util

iqHost = sys.argv[1]
iqUser = sys.argv[2]
iqPwd = sys.argv[3]

iq = nexusiq.NexusIQData(iqHost, iqUser, iqPwd)

outputDir = './datafiles'
workdir = '{}/{}'.format(outputDir, 'policyviolationfiles')
overRidesCsvFile = '{}/{}'.format(outputDir, 'overrides.csv')
overridesDB = fileIO.readOverridesFile(overRidesCsvFile)
appsOverridenDb = []

appReportsJsonFile = '{}/{}'.format(outputDir, 'appreports.json')
appReportsUrlsCsvFile = '{}/{}'.format(outputDir, 'appreportsurls.csv')
appPolicyViolationsJsonFile = '{}/{}'.format(outputDir, 'apppolicyviolations.json')
appPolicyViolationsCsvFile = '{}/{}'.format(outputDir, 'apppolicyviolations.csv')


def applicationHasOverride(applicationId):
  exists = False

  for o in overridesDB:
    overrideApplicationId = o[1]

    if overrideApplicationId == applicationId:
      exists = True
      break

  return exists

def componentHasOverride(applicationId, packageUrl):
  exists = False

  for o in overridesDB:
    overrideApplicationId = o[1]
    overridePackageUrl = o[4]

    if overrideApplicationId == applicationId and overridePackageUrl == packageUrl:
      exists = True
      break

  return exists

def getVulnerabilityDetails(reason):
  info = reason.split(' ')
  return info[3], info[10]

def getApplicationEvaluationReports():
  # get all application reports info
  statusCode, applicationEvaluations = iq.getData('/api/v2/reports/applications')

  if statusCode == 200:
    # Write the json data to file
    fileIO.writeJsonFile(appReportsJsonFile, applicationEvaluations)

    for applicationEvaluation in applicationEvaluations:
      applicationId = applicationEvaluation["applicationId"]

      # only consider if the application has an override
      if applicationHasOverride(applicationId):
        applicationName = util.getApplicationName(applicationEvaluation["reportDataUrl"])
        applicationReportUrl = applicationEvaluation["reportDataUrl"]
        stage = applicationEvaluation["stage"]

        line = applicationName + "," + applicationId + "," + applicationReportUrl + "," + stage + "\n"
        appsOverridenDb.append(line)

    fileIO.writeCSVFile(appReportsUrlsCsvFile, "", appsOverridenDb)

  return statusCode

def getPolicyViolationsForOverrideApplications():
  # get the policy violations for each override application

  with open(appPolicyViolationsCsvFile, 'w') as fd:
    fd.write('ApplicationPublicId,ApplicationId,PackageUrl,ComponentHash,PolicyName,PolicyId,PolicyThreatCategory,PolicyThreatLevel,PolicyViolationId,Waived,CVE,Severity\n')
    fd.close()

  # read the app report urls file (it contains applications with overrides) and get the policy violations for each application
  with open(appReportsUrlsCsvFile) as csvfile:
    r = csv.reader(csvfile, delimiter=',')
    for row in r:
      url = row[2]

      # we want the policy violations
      policyReportDataUrl = url.replace('/raw', '/policy')
      statusCode, policyReportData = iq.getData('/' + policyReportDataUrl)

      if statusCode == 200:
        components = policyReportData["components"]
        applicationId = policyReportData["application"]["id"]
        applicationName = policyReportData["application"]["publicId"]

        #  write the json data
        fileIO.writeJsonFile(workdir + "/" + applicationName + ".json", policyReportData)

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
  return 200

def main():
  if not os.path.exists(workdir):
    os.makedirs(workdir)

  if not getApplicationEvaluationReports() == 200:
    sys.exit(-1)

  if not getPolicyViolationsForOverrideApplications() == 200:
    sys.exit(-1)


if __name__ == '__main__':
  main()

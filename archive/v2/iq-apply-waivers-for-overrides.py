
from applib import fileIO

outputDir = './datafiles'

overRidesCsvFile = '{}/{}'.format(outputDir, 'overrides.csv')
appPolicyViolationsCsvFile = '{}/{}'.format(outputDir, 'apppolicyviolations.csv')
summaryCsvFile = '{}/{}'.format(outputDir, 'applywaivers.csv')
cmdFile = '{}/{}'.format(outputDir, "cmdfile.txt")

overridesDb = fileIO.readOverridesFile(overRidesCsvFile)
violationsDb = fileIO.readCsvFile(appPolicyViolationsCsvFile)


def getViolation(applicationId, componentHash, cve):
  applicationPublicId = "none"
  policyViolationId = "none"

  for violation in violationsDb:
    _applicationId = violation[1]
    _componentHash = violation[3]
    _cve = violation[10]

    if _applicationId == applicationId and _componentHash == componentHash and _cve == cve:
      applicationPublicId = violation[0]
      policyViolationId = violation[8]
      break

  return applicationPublicId, policyViolationId


def writeCommand(applicationPublicId, policyViolationId):
  iqUrl = "http://localhost:8070"
  iqUser = "admin"
  iqPwd = "admin123"
  cmd = "curl -u " + iqUser + ":" + iqPwd + " -X POST -H \"Content-Type: application/json\" -d " + "'{\"comment\": \"adding waiver for status override\"}' " + iqUrl + "/api/v2/policyWaivers/application/" + applicationPublicId + "/" + policyViolationId + "\n"
  return cmd

def main():
  summaryDB = []

  with open(cmdFile, 'w') as fd:

    for override in overridesDb:
      applicationId = override[1]
      overrideStatus = override[2]
      packageUrl = override[4]
      componentHash = override[5]
      cve = override[6]

      applicationPublicId, policyViolationId = getViolation(applicationId, componentHash, cve)
      line = packageUrl + "," + cve + "," + overrideStatus + "," + applicationPublicId + "," + policyViolationId + "\n"
      summaryDB.append(line)
      cmd = writeCommand(applicationPublicId, policyViolationId)
      fd.write(cmd)

  csvHeader = "PackageUrl,CVE,OverrideStatus,ApplicationPublicId,PolicyViolationId\n"
  fileIO.writeCSVFile(summaryCsvFile, csvHeader, summaryDB)
  print(cmdFile)

if __name__ == '__main__':
  main()

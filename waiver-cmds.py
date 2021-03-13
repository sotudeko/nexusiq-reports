
from applib import fileIO

outputDir = fileIO.outputDir

summaryCsvFile = '{}/{}'.format(outputDir, 'applywaivers.csv')
cmdFile = '{}/{}'.format(outputDir, "cmdfile.txt")

securityOverridesDb = fileIO.readSecurityOverridesFile()
licenseOverridesDb = fileIO.readSecurityOverridesFile()

violationsDb = fileIO.readOverridesViolationsFile()


def getViolation(violationTYpe, applicationId, componentHash, cve):
  applicationPublicId = "none"
  policyViolationId = "none"

  for violation in violationsDb:
    _type = violation[0]
    _applicationId = violation[2]
    _componentHash = violation[4]
    _cve = violation[11]

    if _type == violationTYpe and _applicationId == applicationId and _componentHash == componentHash and _cve == cve:
      applicationPublicId = violation[1]
      policyViolationId = violation[9]
      break

  return applicationPublicId, policyViolationId


def writeCommand(applicationPublicId, policyViolationId):
  iqUrl = "http://iqurl"
  iqUser = "iquser"
  iqPwd = "iqpwd"
  cmd = "curl -u " + iqUser + ":" + iqPwd + " -X POST -H \"Content-Type: application/json\" -d " + "'{\"comment\": \"adding waiver for status override\"}' " + iqUrl + "/api/v2/policyWaivers/application/" + applicationPublicId + "/" + policyViolationId + "\n"
  return cmd

def main():
  summaryDB = []

  with open(cmdFile, 'w') as fd:

    for override in securityOverridesDb:
      applicationId = override[1]
      overrideStatus = override[2]
      packageUrl = override[4]
      componentHash = override[5]
      cve = override[6]

      applicationPublicId, policyViolationId = getViolation("security", applicationId, componentHash, cve)
      line = packageUrl + "," + cve + "," + overrideStatus + "," + applicationPublicId + "," + policyViolationId + "\n"
      summaryDB.append(line)
      cmd = writeCommand(applicationPublicId, policyViolationId)
      fd.write(cmd)

  csvHeader = "PackageUrl,CVE,OverrideStatus,ApplicationPublicId,PolicyViolationId\n"
  fileIO.writeCSVFile(summaryCsvFile, csvHeader, summaryDB)
  print(cmdFile)

if __name__ == '__main__':
  main()

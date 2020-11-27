
from lib import fileIO

outputDir = './datafiles'

overRidesCsvFile = '{}/{}'.format(outputDir, 'overrides.csv')
appPolicyViolationsCsvFile = '{}/{}'.format(outputDir, 'apppolicyviolations.csv')

overridesDb = fileIO.readCsvFile(overRidesCsvFile)
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


def main():

  for override in overridesDb:
    applicationId = override[1]
    overrideStatus = override[2]
    packageUrl = override[4]
    componentHash = override[5]
    cve = override[6]

    applicationPublicId, policyViolationId = getViolation(applicationId, componentHash, cve)
    line = packageUrl + "," + cve + "," + overrideStatus + "," + applicationPublicId + "," + policyViolationId
    print(line)



if __name__ == '__main__':
  main()

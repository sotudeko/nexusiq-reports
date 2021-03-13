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
workdir = '{}/{}'.format(outputDir, 'violations')

overRidesCsvFile = '{}/{}'.format(outputDir, 'security_overrides.csv')
overRidesDb = []

def getSecurityOverRidesData():
  # get security vulnerabilty override data
  statusCode, overrides = iq.getData('/api/v2/securityOverrides')

  if statusCode == 200:
    # Write the json data to file
    # fileIO.writeJsonFile(overRidesJsonFile, overrides)

    overrides = overrides['securityOverrides']

    for override in overrides:
      comment = override["comment"]
      referenceId = override["referenceId"]
      status = override["status"]
      ownerName = override["owner"]["ownerName"]
      ownerId = override["owner"]["ownerId"]

      for affectedComponent in override["currentlyAffectedComponents"]:
        packageUrl = affectedComponent["packageUrl"]
        componentHash = affectedComponent["hash"]

      # write only if it is format we need
      if not util.overrideFormat(packageUrl):
        continue

      line = ownerName + "," + ownerId + "," + status + "," + comment + "," + packageUrl + "," + componentHash + "," + referenceId + "\n"
      overRidesDb.append(line)

    csvHeader = "ApplicationName,ApplicationId,OverrideStatus,Comment,PackageUrl,ComponentHash,CVE\n"
    fileIO.writeCSVFile(overRidesCsvFile, csvHeader, overRidesDb)

  print(overRidesCsvFile)


def main():
   getSecurityOverRidesData()


if __name__ == '__main__':
  main()

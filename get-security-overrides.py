# get all the security over rides
# writes all data to json file - security_overrides.json
# writes only a-name data to csv file - security_overrides.csv
# writes ApplicationName,ApplicationId,OverrideStatus,Comment,PackageUrl,ComponentHash,CVE

import sys
import os
import os.path
import csv
from applib import nexusiq, fileIO, util

iqHost = sys.argv[1]
iqUser = sys.argv[2]
iqPwd = sys.argv[3]

iq = nexusiq.NexusIQData(iqHost, iqUser, iqPwd)

securityOverRidesJsonFile = fileIO.securityOverRidesJsonFile
securityOverRidesCsvFile = fileIO.securityOverRidesCsvFile
securityOverridesDb = []

def getSecurityOverRidesData():
  statusCode, overrides = iq.getData('/api/v2/securityOverrides')

  if statusCode == 200:
    fileIO.writeJsonFile(securityOverRidesJsonFile, overrides)
    print (securityOverRidesJsonFile)

    for override in overrides['securityOverrides']:

      comment = override["comment"]
      referenceId = override["referenceId"]
      status = override["status"]
      ownerName = override["owner"]["ownerName"]
      ownerId = override["owner"]["ownerId"]

      for affectedComponent in override["currentlyAffectedComponents"]:
        packageUrl = affectedComponent["packageUrl"]
        componentHash = affectedComponent["hash"]

      if not util.isAname(packageUrl):
        continue

      line = ownerName + "," + ownerId + "," + status + "," + comment + "," + packageUrl + "," + componentHash + "," + referenceId + "\n"
      securityOverridesDb.append(line)

    csvHeader = "ApplicationName,ApplicationId,OverrideStatus,Comment,PackageUrl,ComponentHash,CVE\n"
    fileIO.writeCSVFile(securityOverRidesCsvFile, csvHeader, securityOverridesDb)

  print(securityOverRidesCsvFile)


def main():
   getSecurityOverRidesData()


if __name__ == '__main__':
  main()

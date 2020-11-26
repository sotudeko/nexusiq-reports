import json
import requests
import os
import os.path
import sys
import csv
import shutil

iqUrl = sys.argv[1]
iqUser = sys.argv[2]
iqPwd = sys.argv[3]

generateData = True
outputDir = './datafiles'

overRidesJsonFile = '{}/{}'.format(outputDir, 'overrides.json')
overRidesCsvFile = '{}/{}'.format(outputDir, 'overrides.csv')

policyViolationsDb = []
overRidesDb = []

if len(sys.argv) > 4:
  generateData = False


def getNexusIqData(api):
  # access Nexus IQ API
  url = "{}{}".format(iqUrl, api)
  req = requests.get(url, auth=(iqUser, iqPwd), verify=False)

  if req.status_code == 200:
    data = req.json()
  else:
    data = 'Error fetching data'

  return req.status_code, data


def writeJsonFile(jsonFile, jsonData):
  with open(jsonFile, 'w') as fd:
    json.dump(jsonData, fd, indent=4)

  print(jsonFile)

  return

def outputFormat(purl):
  if ":a-name/" in purl or ":npm/" in purl:
    return True
  else:
    return False


def getOverRidesData():
  # get security vulnerabilty override data
  statusCode, overrides = getNexusIqData('/api/v2/securityOverrides')

  if statusCode == 200:
    # Write the json data to file
    writeJsonFile(overRidesJsonFile, overrides)

    overrides = overrides['securityOverrides']

    # write also a summary csv file
    with open(overRidesCsvFile, 'w') as fd:
      fd.write("ApplicationName,ApplicationId,OverrideStatus,Comment,PackageUrl,ComponentHash,CVE\n")
      for override in overrides:
        comment = override["comment"]
        referenceId = override["referenceId"]
        status = override["status"]
        ownerName = override["owner"]["ownerName"]
        ownerId = override["owner"]["ownerId"]

        for affectedComponent in override["currentlyAffectedComponents"]:
          packageUrl = affectedComponent["packageUrl"]
          proprietary = affectedComponent["proprietary"]
          thirdParty = affectedComponent["thirdParty"]
          componentHash = affectedComponent["hash"]

          # write only if it is format we need
          if not outputFormat(packageUrl):
            continue

          line = ownerName + "," + ownerId + "," + status + "," + comment + "," + packageUrl + "," + componentHash + "," + referenceId + "\n"

          # store and also write to file
          overRidesDb.append(line)
          fd.write(line)

  print(overRidesCsvFile)
  return statusCode


def getPolicyIds():
  policyIds = ""
  data = getNexusIqData('/api/v2/policies')
  policies = data['policies]

  for policy in policies:
    name = policy["name"]
    id = policy["id"]

    if name == "Security-Critical" or name == "Security-High" or name == "Security-Medium" or name == "Security-Malicious" or name == "License-Banned" or name == "License-None" or name == "License-Copyleft":
      policyIds += "p=" + id + "&"

  result = policyIds.rstrip('&')

  return result



def main():
  if generateData:
    if not os.path.exists(outputDir):
      os.makedirs(outputDir)

    if not getOverRidesData() == 200:
      sys.exit(-1)

    policyIds = getPolicyIds()
    print(policyIds)




if __name__ == '__main__':
  main()

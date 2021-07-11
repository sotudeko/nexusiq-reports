# read list of application evaluation reports from app_reportsurls.csv
# for each report, get the data and read the list of components in the report and get the license info
# writes data if status = overridden - license_overrides.csv
# writes the app report component information to json file for the each application
# writes applicationName,applicationId,packageUrl,status,licenseStr

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
workdir = fileIO.licenceWorkdir

appReportsUrlsCsvFile = fileIO.appReportsUrlsCsvFile
licenseOverridesCsvFile = fileIO.licenseOverridesCsvFile


def getLicenseOverrides():

  with open(licenseOverridesCsvFile, 'w') as fd:
    fd.write('ApplicationPublicId,ApplicationId,PackageUrl,Status,OverriddenLicense\n')
    fd.close()

  with open(appReportsUrlsCsvFile) as csvfile:
    r = csv.reader(csvfile, delimiter=',')
    for row in r:
      applicationName = row[0]
      applicationId = row[1]
      url = row[2]

      statusCode, policyReportData = iq.getData('/' + url)

      if statusCode == 200:

        components = policyReportData["components"]

        with open(licenseOverridesCsvFile, 'a') as fd:
          for component in components:
            packageUrl = component["packageUrl"]

            if not packageUrl:
              continue

            licenseData = component["licenseData"]

            if not licenseData:
              continue
            
            status = component["licenseData"]["status"]
            if not util.isLicenseOverrideStatus(status):
              continue

            licenseOverride = component["licenseData"]["overriddenLicenses"]
            licenseStr = ""

            for license in licenseOverride:
              overriddenLicenseId = license["licenseId"]
              overriddenLicenseName = license["licenseName"]
              licenseStr = overriddenLicenseId + ":" + overriddenLicenseName + ";"

            licenseStr = licenseStr[:-1]
            line = applicationName + "," + applicationId + "," + packageUrl + "," + status + "," + licenseStr + "\n"
            fd.write(line)
      
            lic_json = workdir + "/" + applicationName + ".json"
            fileIO.writeJsonFile(lic_json, policyReportData)

  print(licenseOverridesCsvFile)
  return


def main():

  getLicenseOverrides()


if __name__ == '__main__':
  main()

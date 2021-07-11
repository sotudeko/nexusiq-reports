import json
import csv

outputDir = './datafiles'
violationsWorkdir = '{}/{}'.format(outputDir, 'violations')
licenceWorkdir = '{}/{}'.format(outputDir, 'licensedata')

appReportsJsonFile = '{}/{}'.format(outputDir, 'app_reports.json')
appReportsUrlsCsvFile = '{}/{}'.format(outputDir, 'app_reportsurls.csv')

securityOverRidesJsonFile = '{}/{}'.format(outputDir, 'security_overrides.json')
securityOverRidesCsvFile = '{}/{}'.format(outputDir, 'security_overrides.csv')

licenseOverridesCsvFile = '{}/{}'.format(outputDir, 'license_overrides.csv')

overrideViolationsCsvFile = '{}/{}'.format(outputDir, 'overrides_violations.csv')


def writeCSVFile(csvFile, csvHeader, csvData):
    with open(csvFile, 'w') as fd:
        fd.write(csvHeader)
        for line in csvData:
            fd.write(line)
    # print(csvFile)
    return

def writeJsonFile(jsonFile, jsonData):
    with open(jsonFile, 'w') as fd:
        json.dump(jsonData, fd, indent=4)

    # print(jsonFile)
    return

def readAppsReportsUrlsFile():
    reports = []

    with open(appReportsUrlsCsvFile) as csvfile:
        csvdata = csv.reader(csvfile, delimiter=',')
        for r in csvdata:
            reports.append(r)

    return reports

def readSecurityOverridesFile():
    overRidesDb = []
    rownumber = 0
    with open(securityOverRidesCsvFile) as csvfile:
        csvdata = csv.reader(csvfile, delimiter=',')
        for r in csvdata:
            if rownumber == 0:
                rownumber += 1
            else:
                rownumber += 1
                overRidesDb.append(r)

    return overRidesDb

def readLicenseOverridesFile():
    overRidesDb = []
    rownumber = 0
    with open(licenseOverridesCsvFile) as csvfile:
        csvdata = csv.reader(csvfile, delimiter=',')
        for r in csvdata:
            if rownumber == 0:
                rownumber += 1
            else:
                rownumber += 1
                overRidesDb.append(r)

    return overRidesDb

def readOverridesViolationsFile():
    violationsDb = []
    rownumber = 0
    with open(overrideViolationsCsvFile) as csvfile:
        csvdata = csv.reader(csvfile, delimiter=',')
        for r in csvdata:
            if rownumber == 0:
                rownumber += 1
            else:
                rownumber += 1

                line = r[0] + ',' + r[1] + ',' + r[2] + ',' + r[3] + ',' + r[4] + ',' + r[5] + ',' + r[6] + ',' + r[7] + ',' + r[8] + ',' + r[9] + ',' + r[10] + ',' + r[11]
                violationsDb.append(r)

    return violationsDb
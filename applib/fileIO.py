import json
import csv

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

def readOverridesFile(overRidesCsvFile):
    overRidesDb = []
    rownumber = 0
    with open(overRidesCsvFile) as csvfile:
        csvdata = csv.reader(csvfile, delimiter=',')
        for r in csvdata:
            if rownumber == 0:
                rownumber += 1
            else:
                rownumber += 1
                overRidesDb.append(r)

    return overRidesDb

def readCsvFile(appPolicyViolationsCsvFile):
    violationsDb = []
    rownumber = 0
    with open(appPolicyViolationsCsvFile) as csvfile:
        csvdata = csv.reader(csvfile, delimiter=',')
        for r in csvdata:
            if rownumber == 0:
                rownumber += 1
            else:
                rownumber += 1

                line = r[0] + ',' + r[1] + ',' + r[2] + ',' + r[3] + ',' + r[4] + ',' + r[5] + ',' + r[6] + ',' + r[7] + ',' + r[8] + ',' + r[9] + ',' + r[10] + ',' + r[11]
                violationsDb.append(r)

    return violationsDb
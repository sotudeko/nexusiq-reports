import json
import requests
import os
import os.path
import sys
import csv
import shutil

iqUrl = sys.argv[1]
iquser = sys.argv[2]
iqpwd = sys.argv[3]


generateData = True
outputDir = './datafiles'

overRidesJsonFile = '{}/{}'.format(outputDir, 'overrides.json')
overRidesCsvFile = '{}/{}'.format(outputDir, 'overrides.csv')

appReportsJsonFile = '{}/{}'.format(outputDir, 'appreports.json')
appReportsUrlsCsvFile = '{}/{}'.format(outputDir, 'appreportsurls.csv')
appIssuesStatusCsvFile = '{}/{}'.format(outputDir, 'appissuesstatus.csv')

appPolicyViolationsCsvFile = '{}/{}'.format(outputDir, 'apppolicyviolations.csv')

statusSummaryCsvFile = '{}/{}'.format(outputDir, 'statussummary.csv')

overRidesDb = []
policyViolationsDb = []
secLicIssuesDb = []


if len(sys.argv) > 4:
	generateData = False


def getNexusIqData(api):
    # access Nexus IQ API
    url = "{}{}" . format(iqUrl, api)
    req = requests.get(url, auth=(iquser, iqpwd), verify=False)

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


def applicationHasOverride(applicationId):
	exists = False

	for o in overRidesDb:
		info = o.split(',')

		overrideApplicationId = info[1]

		if overrideApplicationId == applicationId:
			exists = True
			break
	
	return exists


def getApplicationName(urlPath):
	l = urlPath.split('/')
	return(l[3])


def componentHasOverride(applicationId, packageUrl):
	exists = False

	for o in overRidesDb:
		info = o.split(',')
		overrideApplicationId = info[1]
		overridePackageUrl = info[4]

		if overrideApplicationId == applicationId and overridePackageUrl == packageUrl:
			exists = True
			break
	
	return exists


def outputFormat(purl):
	if ":a-name/" in purl or ":npm/" in purl:
		return True
	else:
		return False


def getPolicyViolationLine(applicationId, componentHash):
	line = ""

	for i in policyViolationsDb:
		info = i.split(',')
		pvApplicationId = info[1]
		pvComponentHash = info[3]

		if pvComponentHash == componentHash and pvApplicationId == applicationId:
			# PolicyName,PolicyThreatLevel,Waived,PolicyId,PolicyViolationId
			line = info[4] + "," + info[7] + "," + info[9].rstrip("\n") + "," + info[5] + "," + info[8]
			break

	return line.rstrip("\n")


def getSecLicIssueLine(componentHash, cve):
	line = ""

	for i in secLicIssuesDb:
		info = i.split(',')
		issueComponentHash = info[1]
		issueCve = info[3]

		if issueComponentHash == componentHash and issueCve == cve:
			line = info[4] + "," + info[5] + "," + info[6]
			break

	return line.rstrip("\n")


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

						line = ownerName + "," + ownerId + "," + status + "," + comment + "," + packageUrl +  "," + componentHash + "," + referenceId + "\n"

						# store and also write to file 
						overRidesDb.append(line)
						fd.write(line)

	print(overRidesCsvFile)
	return statusCode



# def getSecurityScore(applicationName, hash, findCve):
# 	return 1, "none"
# 	print (secLicIssuesDb)
# 	for issue in secLicIssuesDb:
# 		cves = issue[3].split(';')
# 		licenseStatus = issue[4]
# 		licenseStatus = licenseStatus[:-1]
# 		cveScore = 0

# 		for c in cves:
# 			el = c.split(':')
# 			cve = el[0]
# 			status = el[1]
# 			score = el[2]

# 			if cve == findCve:
# 				cveScore = score

# 	return cveScore, licenseStatus


def getApplicationEvaluationReports():
    # get all application reports info
    statusCode, applicationEvaluations = getNexusIqData('/api/v2/reports/applications')

    if statusCode == 200:
         # Write the json data to file
        writeJsonFile(appReportsJsonFile, applicationEvaluations)

        # Get the Url of each report and write to CSV file
        with open(appReportsUrlsCsvFile, 'w') as fd:
                for applicationEvaluation in applicationEvaluations:
                    applicationName = getApplicationName(applicationEvaluation["reportDataUrl"])
                    applicationReportUrl = applicationEvaluation["reportDataUrl"]
                    applicationId = applicationEvaluation["applicationId"]
                    stage = applicationEvaluation["stage"]
                    
                    # only write the details if the application has an override
                    if applicationHasOverride(applicationId):
                        line = applicationId + "," + stage + "," + applicationReportUrl + "\n"
                        fd.write(line)
    else:
        print(str(statusCode) + ': ' + applicationEvaluations + ' - Application Reports')

    print(appReportsUrlsCsvFile)
    return statusCode


def writeAppReportUrlsCsvFile(applicationEvaluations):
	with open(appReportsUrlsCsvFile, 'w') as fd:
			for applicationEvaluation in applicationEvaluations:
				applicationName = getApplicationName(applicationEvaluation["reportDataUrl"])
				applicationReportUrl = applicationEvaluation["reportDataUrl"]

				# only write the details if the application has an override
				if applicationHasOverride(applicationName):
					line = applicationName + "," + applicationReportUrl + "\n"
					fd.write(line)

	print(appReportsUrlsCsvFile)
	return


def getPolicyViolationsForOverrideApplications():
	# get the policy violations for each override application 

	with open(appPolicyViolationsCsvFile, 'w') as fd:
			fd.write('ApplicationName,ApplicationId,PackageUrl,ComponentHash,PolicyName,PolicyId,PolicyThreatCategory,PolicyThreatLevel,PolicyViolationId,Waived\n')
			fd.close()

    # read the app report urls file (it contains on applications with overrides)
	with open(appReportsUrlsCsvFile) as csvfile:
			r = csv.reader(csvfile, delimiter=',')
			for row in r:
				url = row[2]

                # append the policy violations for this application report to the output csvfile
				writePolicyViolations(url)

	print(appPolicyViolationsCsvFile)
	return 200


def writePolicyViolations(url):

    # we want the policy violations
	policyReportDataUrl = url.replace('/raw', '/policy')
	statusCode, policyReportData = getNexusIqData('/' + policyReportDataUrl)

	if not statusCode == 200:
		print(str(statusCode) + ': ' + policyReportData + ' - ' + policyReportDataUrl)
		return statusCode

	components = policyReportData["components"]
	applicationId = policyReportData["application"]["id"]
	applicationName = policyReportData["application"]["name"]
	counts = policyReportData["counts"]
	reportTime = policyReportData["reportTime"]
	initiator = policyReportData["initiator"]

    #  write the data
	with open(appPolicyViolationsCsvFile, 'a') as fd:
			for component in components:
				componentHash = component["hash"]
				packageUrl  = component["packageUrl"]

				if not packageUrl:
					packageUrl = "none"

				# write only if it is format we need
				if not outputFormat(packageUrl):
					continue

				# write only if this component has an override
				if not componentHasOverride(applicationId, packageUrl):
					continue

				policyName = ""
				waived = ""

				violations = component['violations']

				for violation in violations:
					policyName = violation['policyName']
					policyId = violation['policyId']
					waived = violation['waived']
					grandfathered = violation['grandfathered']
					policyThreatCategory = violation['policyThreatCategory']
					policyThreatLevel = violation['policyThreatLevel']
					policyViolationId = violation['policyViolationId']

					# Only write if above threat level threshold
					if policyThreatLevel >= 7:
						line = applicationName + "," + applicationId + "," + packageUrl + "," + componentHash + "," + policyName + "," + policyId + "," + policyThreatCategory + "," + str(policyThreatLevel) + "," + policyViolationId + "," + str(waived) + "\n"

						# store and also write to file 
						policyViolationsDb.append(line)
						fd.write(line)
	return


def getSecLicIssuesForOverrideApplications():
	with open(appIssuesStatusCsvFile, 'w') as fd:
			fd.write('ApplicationId,ComponentHash,PackageUrl,CVE,SecurityScore,VulnStatus,LicenceStatus\n')
			fd.close()

    # read the app report urls file (it contains on applications with overrides)
	with open(appReportsUrlsCsvFile) as csvfile:
			r = csv.reader(csvfile, delimiter=',')
			for row in r:
				applicationId = row[0]
				url = row[2]

                # append the security/license issues and status for the application report to the output csvfile
				writeSecLicIssues(applicationId, url)

	print(appIssuesStatusCsvFile)
	return 200


def writeSecLicIssues(applicationId, url):

    # get the report raw data
	statusCode, rawData = getNexusIqData('/' + url)

	if not statusCode == 200:
		print(str(statusCode) + ': ' + rawData + ' - ' + url)
		return	
        
	components = rawData["components"]

    # write the data
	with open(appIssuesStatusCsvFile, 'a') as fd:
			for component in components:
				hash = component["hash"]
				packageUrl  = component["packageUrl"]

				licenseData = component["licenseData"]
				if licenseData:
					licenseStatus = licenseData["status"]
				else:
					licenseStatus = 'none'

				if not packageUrl:
					packageUrl = "none"

				# write only if it is format we need
				if not outputFormat(packageUrl):
					continue

				# write only if this component has an override
				if not componentHasOverride(applicationId, packageUrl):
					continue

				if type(component["securityData"]) is dict:
					securityIssues = component["securityData"]["securityIssues"]

					if len(securityIssues) > 0:
						for securityIssue in securityIssues:
							# if not securityIssue["status"] == "Open" and licenseStatus == "Open":
							line = applicationId + "," + hash + "," + packageUrl + "," + securityIssue["reference"] + "," + str(securityIssue["severity"]) + "," + securityIssue["status"] + "," + licenseStatus + "\n"
							secLicIssuesDb.append(line)
							fd.write(line)
	
	return


def makeStatusSummary():

	with open(statusSummaryCsvFile, 'w') as fd:
			fd.write('ApplicationName,ApplicationId,OverrideStatus,Comment,PackageUrl,ComponentHash,CVE,SecurityScore,VulnStatus,LicenseStatus,PolicyName,PolicyThreatLevel,Waived,PolicyId,PolicyViolationId\n')
			with open(overRidesCsvFile) as csvfile:
					# ApplicationName,ApplicationId,OverrideStatus,Comment,PackageUrl,ComponentHash,CVE

					r = csv.reader(csvfile, delimiter=',')
					lineCount = 0
					for row in r:
						if lineCount == 0:
							lineCount += 1
						else:
							lineCount += 1

							applicationId = row[1]
							componentHash = row[5]
							cve = row[6]

							issueLine = getSecLicIssueLine(componentHash, cve)
							pvLine = getPolicyViolationLine(applicationId, componentHash)

							line = '{},{},{},{},{},{},{},{},{}\n'.format(row[0], row[1], row[2], row[3], row[4], row[5], row[6], issueLine, pvLine)
							fd.write(line)

	print(statusSummaryCsvFile)
	return


def main():

    if generateData:
        if not os.path.exists(outputDir):
            os.makedirs(outputDir)

        if not getOverRidesData() == 200:
            sys.exit(-1)

        if not getApplicationEvaluationReports() == 200:		
            sys.exit(-1)

        if not getPolicyViolationsForOverrideApplications() == 200:
            sys.exit(-1)

        if not getSecLicIssuesForOverrideApplications() == 200:
            sys.exit(-1)

    # summary report
    makeStatusSummary()


if __name__ == '__main__':
	main()

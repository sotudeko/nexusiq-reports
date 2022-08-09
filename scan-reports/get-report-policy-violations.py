
import sys
import csv
import requests
import json

iqurl = sys.argv[1]
iquser = sys.argv[2]
iqpwd = sys.argv[3]

application_name = 'webgoat'
stage = 'build'
policy_name = 'Security-High'
package_url = 'pkg:maven/com.h2database/h2@1.4.187?type=jar'
cve = 'CVE-2022-23221'

csvfile = "list-of-violations.csv"


def pretty_json(json_data):
  json_object = json.loads(json_data)
  json_formatted_str = json.dumps(json_object, indent=2)
  print(json_formatted_str)
  return


def get_nexusiq_data(iqapi):
  url = "{}/{}" . format(iqurl, iqapi)

  # print("fetching data from " + url)

  req = requests.get(url, auth=(iquser, iqpwd), verify=False)
  status_code = req.status_code

  if status_code == 200:
    res = req.json()
  else:
    res = "Error fetching data"

  return status_code, res


def getApplicationId(find_application_name):
  found_id = ""
  status_code, data = get_nexusiq_data('api/v2/applications')

  applications = data["applications"]

  for application in applications:

    application_public_id = application["publicId"]
    application_name = application["name"]
    application_id = application["id"]

    if find_application_name == application_public_id:
      found_id = application_id
      break

  return found_id


def getApplicationEvaluationReportUrl(find_application_id, find_stage):
  statusCode, application_evaluation_reports = get_nexusiq_data('api/v2/reports/applications?publicId=' + find_application_id)

  for application_evaluation_report in application_evaluation_reports:
    application_id = application_evaluation_report["applicationId"]

    applicationReportUrl = application_evaluation_report["reportDataUrl"]
    stage = application_evaluation_report["stage"]

    if application_id == find_application_id and stage == find_stage:
      evaluationDate = application_evaluation_report["evaluationDate"]
      latestReportHtmlUrl = application_evaluation_report["latestReportHtmlUrl"]
      reportHtmlUrl = application_evaluation_report["reportHtmlUrl"]
      embeddableReportHtmlUrl = application_evaluation_report["embeddableReportHtmlUrl"]
      reportPdfUrl = application_evaluation_report["reportPdfUrl"]
      reportDataUrl = application_evaluation_report["reportDataUrl"]
      break

  return reportDataUrl


def getVulnerabilityDetails(reason):
  cve = "no-cve"
  severity = "no-severity"

  info = reason.split(' ')

  if len(info) == 11:
    cve = info[3]
    severity = info[10]

  # remove close bracket at the end of severity
  severity = severity[:-1]

  return cve, severity


def getLicenseDetails(reason):
  info = reason.split(' ')
  return info[4], info[8]


def getPolicyViolations(report_url, find_policy_name, find_package_url, find_cve):

  policyReportDataUrl = report_url.replace('/raw', '/policy')
  statusCode, policyReportData = get_nexusiq_data(policyReportDataUrl)

  if statusCode == 200:
    applicationId = policyReportData["application"]["id"]
    applicationName = policyReportData["application"]["publicId"]
    components = policyReportData["components"]


    with open(csvfile, 'w') as fd:
      writer = csv.writer(fd)

      line = []
      line.append("Policy Name")
      line.append("Threat Level")
      line.append("Application Name")
      line.append("Package Url")
      line.append("CVE")
      line.append("Waived")
      line.append("Component Hash")
      line.append("Severity")
      line.append("Policy Id")
      line.append("Policy Violation Id")
      line.append("Application Id")

      print(line)
      writer.writerow(line)

      for component in components:
          componentHash = component["hash"]
          packageUrl = component["packageUrl"]

          if not packageUrl:
            packageUrl = "none"

          if not packageUrl == find_package_url:
            continue

          policyName = ""
          waived = ""
          reason = ""

          violations = component['violations']

          for violation in violations:
            policyThreatLevel = violation['policyThreatLevel']

            if policyThreatLevel >= 7:
              policyName = violation['policyName']
              policyId = violation['policyId']
              waived = violation['waived']
              policyThreatCategory = violation['policyThreatCategory']
              policyViolationId = violation['policyViolationId']

              if policyThreatCategory == "QUALITY":
                continue

              cve = ""
              severity = ""

              if  policyThreatCategory == "SECURITY" and policyName == find_policy_name:
                constraints = violation['constraints']
                for constraint in constraints:
                  conditions = constraint['conditions']

                  for condition in conditions:
                    reason = condition['conditionReason']
                    cve, severity = getVulnerabilityDetails(reason)

                    # remove close bracket at the end
                    # severity = severity[:-1]

                    if not find_cve == cve:
                      continue

                    line = []
                    line.append(policyName)
                    # line.append(policyThreatCategory.lower())
                    line.append(str(policyThreatLevel))
                    line.append(applicationName)
                    line.append(packageUrl)
                    line.append(cve)
                    line.append(str(waived))
                    line.append(componentHash)
                    line.append(severity)
                    line.append(policyId)
                    line.append(policyViolationId)
                    line.append(applicationId)

                    print(line)
                    writer.writerow(line)

  return


def main():



  application_id = getApplicationId(application_name)

  report_url = getApplicationEvaluationReportUrl(application_id, stage)

  getPolicyViolations(report_url, policy_name, package_url, cve)


if __name__ == '__main__':
  main()

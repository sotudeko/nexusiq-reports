import json
import csv
import os
import shutil
import sys
import requests


iqurl = sys.argv[1]
iquser = sys.argv[2]
iqpwd = sys.argv[3]

iqapi = 'api/v2'

def getNexusIqData(end_point):
    url = "{}/{}/{}" . format(iqurl, iqapi, end_point)

    req = requests.get(url, auth=(iquser, iqpwd), verify=False)

    if req.status_code == 200:
        res = req.json()
    else:
        res = "Error fetching data"

    return res



def getApplicationName(urlPath):
    l = urlPath.split('/')
    return(l[3])


def getRolesAndUsers(obj, data):
    opfile = obj + ".csv"

    with open(opfile, 'w') as fd:
            writer = csv.writer(fd)

            line = []
            line.append("ApplicationName")
            line.append("EvaluationDate")

            writer.writerow(line)

            for d in data:
                id = d["id"]
                name = d["name"]

                # if application
                # publicId = d["publicId"]
                # organizationId = d["organizationId"]

                line = []
                line.append(name)
                line.append(id)

                writer.writerow(line)

    print(opfile)

    return


def print_jsonfile(jsonfile, json_data):
    output_file = "{}{}".format(jsonfile, ".json")
    json_formatted = json.dumps(json_data, indent=2)

    with open(output_file, 'w') as outfile:
        json.dump(json_data, outfile, indent=2)

    print(output_file)
    return

def main():

    organizations = getNexusIqData('organizations')
    print_jsonfile("organizations", organizations)
    getRolesAndUsers("orgs", organizations["organizations"])

    applications = getNexusIqData('applications')
    print_jsonfile("applications", applications)
    getRolesAndUsers("apps", applications["applications"])


if __name__ == '__main__':
    main()
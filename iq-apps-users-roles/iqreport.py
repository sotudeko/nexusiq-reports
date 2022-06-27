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
rolesDb = {}



def getNexusIqData(end_point):
    url = "{}/{}/{}" . format(iqurl, iqapi, end_point)

    req = requests.get(url, auth=(iquser, iqpwd), verify=False)

    if req.status_code == 200:
        res = req.json()
    else:
        res = "Error fetching data"

    return res


def setRolesDb():
    roles =  getNexusIqData('roles')

    for role in roles["roles"]:
        id = role["id"]
        name = role["name"]
        rolesDb[id] = name

    return


def getReport(obj, data):
    opfile = obj + ".csv"

    with open(opfile, 'w') as fd:
            writer = csv.writer(fd)

            line = []
            line.append("Name")
            line.append("Role")
            line.append("Members")

            writer.writerow(line)

            for d in data:
                id = d["id"]
                name = d["name"]

                # if application
                # publicId = d["publicId"]
                # organizationId = d["organizationId"]

                line = []
                line.append(name)

                endpoint = "{}/{}/{}" . format("roleMemberships", obj, id)

                rolesdata = getNexusIqData(endpoint)
                role, ug = getRolesAndUsers(rolesdata["memberMappings"])

                line.append(role)
                line.append(ug)
                
                writer.writerow(line)


    print(opfile)

    return


def getRolesAndUsers(data):
    ug = ""

    for d in data:
        role = rolesDb.get(d["roleId"]) 

        for m in d["members"]:
            userOrGroupName = m["userOrGroupName"]
            ug += userOrGroupName + ","

        # ug = ug[:-1]

    return role, ug


def print_jsonfile(jsonfile, json_data):
    output_file = "{}{}".format(jsonfile, ".json")
    json_formatted = json.dumps(json_data, indent=2)

    with open(output_file, 'w') as outfile:
        json.dump(json_data, outfile, indent=2)

    print(output_file)
    return



def main():

    setRolesDb()

    organizations = getNexusIqData('organizations')
    print_jsonfile("organizations", organizations)
    getReport("organization", organizations["organizations"])

    applications = getNexusIqData('applications')
    print_jsonfile("applications", applications)
    getReport("application", applications["applications"])


if __name__ == '__main__':
    main()
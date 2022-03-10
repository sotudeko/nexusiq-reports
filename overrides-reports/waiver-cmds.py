# use this script generate apply waivers command
# you may want edit  this to output fields you need andaslo add conditionals on the status

from applib import fileIO
import csv

outputDir = fileIO.outputDir

summaryCsvFile = '{}/{}'.format(outputDir, 'applywaivers.csv')
cmdFile = '{}/{}'.format(outputDir, "cmdfile.txt")

def makeCommand(applicationPublicId, policyViolationId, comment):
  _comment = "adding waiver for status override"

  if not comment == "":
    _comment = comment

  # add your iq url, user and password
  iqUrl = "http://iqurl"
  iqUser = "iquser"
  iqPwd = "iqpwd"
  cmd = "curl -u " + iqUser + ":" + iqPwd + " -X POST -H \"Content-Type: application/json\" -d " + "'{\"comment\": \"" + _comment + "\"}' " + iqUrl + "/api/v2/policyWaivers/application/" + applicationPublicId + "/" + policyViolationId + "\n"
  return cmd


def main():
  
  iqUrl = "http://iqurl"
  iqUser = "iquser"
  iqPwd = "iqpwd"

  rownumber = 0

  with open(fileIO.overrideViolationsCsvFile) as csvfile:
    csvdata = csv.reader(csvfile, delimiter=',')
    for r in csvdata:
      if rownumber == 0:
        rownumber += 1
      else:
        with open(cmdFile, 'a') as fd:
          applicationName = r[1]
          comment = r[13]
          policyViolationId = r[8]
          cmd = makeCommand(applicationName, policyViolationId, comment)
          fd.write(cmd)

  print(cmdFile)

  
if __name__ == '__main__':
  main()



def getApplicationName(urlPath):
    l = urlPath.split('/')
    return(l[3])


def isAname(purl):
    #if ":a-name/" in purl or ":npm/" in purl:
    if ":a-name/" in purl:
        return True
    else:
        return False


def isLicenseOverrideStatus(status):
    if "Overridden" in status:
        return True
    else:
        return False


# def applicationHasOverride(applicationId):
#   exists = False

#   for o in overridesDb:
#     overrideApplicationId = o[1]

#     if overrideApplicationId == applicationId:
#       exists = True
#       break

#   return exists


# def componentHasSecurityOverride(applicationId, packageUrl):
#   exists = False

#   for o in overridesDb:
#     overrideApplicationId = o[1]
#     overridePackageUrl = o[4]

#     if overrideApplicationId == applicationId and overridePackageUrl == packageUrl:
#       exists = True
#       break

#   return exists

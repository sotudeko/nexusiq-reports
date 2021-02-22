
def overrideFormat(purl):
    if ":a-name/" in purl or ":npm/" in purl:
        return True
    else:
        return False

def getApplicationName(urlPath):
    l = urlPath.split('/')
    return(l[3])

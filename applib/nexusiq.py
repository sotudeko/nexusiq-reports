import requests

class NexusIQData(object):
    def __init__(self, iqUrl, iqUser, iqPwd):
        self.iqUrl = iqUrl
        self.iqUser = iqUser
        self.iqPwd = iqPwd

    def getData(self, api):
        url = "{}{}" . format(self.iqUrl, api)
        req = requests.get(url, auth=(self.iqUser, self.iqPwd), verify=False)

        if req.status_code == 200:
            data = req.json()
        else:
            data = 'Error fetching data'

        return req.status_code, data

import requests

SUCCESS = 0
SOFT_FAIL = 1
HARD_FAIL = 2

class Storage:
    def __init__(self, server, port, app, version):
        self.server = server
        self.port = port
        self.app = app
        self.version = version

    def version(self):
        data = {}
        try:
            res = requests.get('http://{}:{}/app/versioncode/{}'.format(self.server, self.port, self.app))
            data = res.text
            data = data[data.find("[")+1:data.find("]")]
        except Exception as e:
            data = "-1"
        finally:
            return data

    def apk(self, folder=None):
        if folder is not None:
            apk_path = '{}/{}'.format(folder, self.app)
        else:
            apk_path = '{}'.format(self.app)
        try:
            res = requests.get('http://{}:{}/app/apk/{}/{}'.format(self.server, self.port, self.app, self.version), stream=True)
            res.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xxx
            if res.content != b'null\n':  # Storage server returns 'null|n' when the APK is not available
                with open(apk_path, 'wb') as f:
                    for chunk in res.iter_content(chunk_size=128):
                        f.write(chunk)
            else:
                return SOFT_FAIL, 'Unavailable APK, "null" returned'
        except requests.exceptions.ConnectionError as e:
            return HARD_FAIL, str(e)
        except requests.exceptions.Timeout as e:
            return HARD_FAIL, str(e)
        except requests.exceptions.HTTPError as e:
            return SOFT_FAIL, str(e)
        else:
            return SUCCESS, apk_path


    def policy(self, folder=None):
        if folder is not None:
            path_policy = '{}/{}'.format(folder, self.app)
        else:
            path_policy = '{}'.format(self.app)
        try:
            res = requests.get('http://{}:{}/app/privacypolicy/{}/{}/txt'.format(self.server, self.port, self.app,
                                                                                 self.version), stream=True)
            res.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xxx
            if res.text != 'null\n':  # Storage server returns 'null|n' when the privacy policy is not available
                with open(path_policy, 'w', encoding='utf-8') as f:
                    f.write(res.text)
            else:
                return SOFT_FAIL, 'Unavailable privacy policy, "null" returned'
        except requests.exceptions.ConnectionError as e:
            return HARD_FAIL, str(e)
        except requests.exceptions.Timeout as e:
            return HARD_FAIL, str(e)
        except requests.exceptions.HTTPError as e:
            return SOFT_FAIL, str(e)
        else:
            return SUCCESS, path_policy


# Unit testing
import unittest

class Test_Storage(unittest.TestCase):
    def test_apk(self):
        storage_ip = "34.78.85.82"
        storage_port = "30500"
        app_test = 'com.appmag.endless.temple.princessfinaljungleozrunfrozen'
        #app_test = 'com.Rue21.shopping'
        version_test = '3'
        # Asserting detection of down storage server
        exitcode, value = Storage("1.1.1.1", storage_port, app_test, version_test).apk()
        self.assertEqual(exitcode, HARD_FAIL, 'It does not detect down server')
        # Asserting detection of an unavailable policy
        exitcode, value = Storage(storage_ip, storage_port, 'com.unavailable.app', version_test).apk()
        self.assertEqual(exitcode, SOFT_FAIL, 'It does not detect unavailable resource')
        # Asserting download of an available privacy policies
        exitcode, value = Storage(storage_ip, storage_port, app_test, version_test).apk()
        self.assertEqual(exitcode, SUCCESS, 'It does not download an available resource')
if __name__ == '__main__':
    unittest.main()

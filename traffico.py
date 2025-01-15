

# ############################################################################
#                             TRAFFIC ANALYSIS WRAPPERS
#############################################################################
import io
import multiprocessing
import shutil
import zipfile
import time
import requests
import json
import os


class Traffic:
    def __init__(self, server, port, device, apk, testing_label, version, app):
        self.server = server
        self.port = port
        self.device = device
        self.apk = apk
        self.testing_label = testing_label
        self.version = version
        self.app = app

    def configure(self):
        data = {}
        try:
            res = requests.get('http://{}:{}/config'.format(self.server, self.port),
                               params={'ip': self.device, 'testing_label': self.testing_label, 'version': self.version,
                                       'app': self.app})
            data = json.loads(res.text)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return data['Ok'], data['Msg']

    def configure2(self, name):
        data = {}
        try:
            res = requests.get('http://{}:{}/config'.format(self.server, self.port), params={'ip': self.device, 'name': name, 'testing_label': self.testing_label, 'version': self.version})
            data = json.loads(res.text)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return data['Ok'], data['Msg']

    def upload(self):
        data = {}
        try:
            file = {'apk': open(self.apk, 'rb')}
            res = requests.post('http://{}:{}/upload'.format(self.server, self.port), files=file)
            data = json.loads(res.text)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return data['Ok'], data['Msg']

    def phaseOne(self, timeout, permissions=True, reboot=False):
        data = {}
        try:
            res = requests.get('http://{}:{}/phase-one'.format(self.server, self.port), params={'timeout': timeout,
                                                                                                'permissions': permissions,
                                                                                                'reboot': reboot})
            data = json.loads(res.text)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
            data['Code'] = 40
        finally:
            return data['Ok'], data['Msg'], data['Code']

    def phaseTwo(self, timeout, monkey=True):
        data = {}
        try:
            res = requests.get('http://{}:{}/phase-two'.format(self.server, self.port), params={'timeout': timeout, 'monkey': monkey})
            data = json.loads(res.text)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
            data['Code'] = 40
        finally:
            return data['Ok'], data['Msg'], data['Code']

    def analysis(self):
        data = {}
        try:
            res = requests.get('http://{}:{}/analysis'.format(self.server, self.port))
            data = json.loads(res.text)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return data['Ok'], data['Msg']

    def result(self, folder=None):
        data = {'Ok': True}
        try:
            res = requests.get('http://{}:{}/result'.format(self.server, self.port))
            data['Msg'] = res.text
            if folder is not None:
                with open('{}/{}-pii.privapp.log'.format(folder, os.path.basename(self.apk.decode('utf-8'))), 'wb') as f:
                    for chunk in res.iter_content(chunk_size=128):
                        f.write(chunk)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return data['Ok'], data['Msg']

    def screenshotPhaseOne(self, folder):
        data = {'Ok': True, 'Msg': None}
        try:
            res = requests.get('http://{}:{}/screenshot-phase-one'.format(self.server, self.port), stream=True)
            if res.status_code == 200:
                # with open('{}/{}-first.tar'.format(folder, os.path.basename(self.apk.decode('utf-8'))), 'wb') as f:
                with open(os.path.join(folder, "{}-fp-screenshoot".format(os.path.basename(self.apk))), 'wb') as f:
                    res.raw.decode_content = False
                    shutil.copyfileobj(res.raw, f)
                    #for chunk in res.iter_content(chunk_size=128):
                    #    f.write(chunk)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return (data['Ok'], data['Msg'])

    def screenshotPhaseTwo(self, folder):
        data = {'Ok': True, 'Msg': None}
        try:
            res = requests.get('http://{}:{}/screenshot-phase-two'.format(self.server, self.port), stream=True)
            if res.status_code == 200:
                with open('{}/{}-sp.screenshot'.format(folder, os.path.basename(self.apk.decode('utf-8'))), 'wb') as f:
                    for chunk in res.iter_content(chunk_size=128):
                        f.write(chunk)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return (data['Ok'], data['Msg'])

    def rawPhaseOne(self, folder):
        data = {'Ok': True, 'Msg': None}
        try:
            res = requests.get('http://{}:{}/raw-phase-one'.format(self.server, self.port), stream=True)
            with open('{}/{}-raw-first.out'.format(folder, os.path.basename(self.apk.decode('utf-8'))), 'wb') as f:
                for chunk in res.iter_content(chunk_size=128):
                    f.write(chunk)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return (data['Ok'], data['Msg'])

    def rawPhaseTwo(self, folder):
        data = {'Ok': True, 'Msg': None}
        try:
            res = requests.get('http://{}:{}/raw-phase-two'.format(self.server, self.port), stream=True)
            with open('{}/{}-raw-second.out'.format(folder, os.path.basename(self.apk.decode('utf-8'))), 'wb') as f:
                for chunk in res.iter_content(chunk_size=128):
                    f.write(chunk)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return (data['Ok'], data['Msg'])

    def cert(self):
        data = {}
        try:
            res = requests.get('http://{}:{}/cert'.format(self.server, self.port))
            data = json.loads(res.text)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return (data['Ok'], data['Msg'])

    def hooker(self):
        data = {}
        try:
            res = requests.get('http://{}:{}/hooker'.format(self.server, self.port))
            data = json.loads(res.text)
        except Exception as e:
            data['Ok'] = False
            data['Msg'] = str(e)
        finally:
            return (data['Ok'], data['Msg'])

    def sanitize(self):
        try:
            res = requests.get('http://{}:{}/sanitize'.format(self.server, self.port))
        except Exception as e:
            print(str(e))
# data = json.loads(res.text)

# TESTING
# t = Traffic("192.168.1.201", "4000", "aee4ad920306", "/privapp/app/results/it/apks/app_376.apk", "Label_Tuning")
def manualPhaseOne(app):
    t = Traffic("192.168.1.202", "4002", "aee4ad920306", 'base.apk', "pinningtest", 1, app)
    #t = Traffic("192.168.1.202", "4003", "3d3799289906", 'base.apk', "pinningtest", 1, app)
    print(t.configure())
    print(t.upload())
    #print(t.configure2(app))
    print(t.phaseOne(60, True, False))
    print(t.phaseTwo(120, True))
    print(t.analysis())
    print(t.result())
    time.sleep(5)
    print(t.sanitize())

def manualPhaseTwo(app):
    t = Traffic("192.168.1.201", "4002", "aee4ad920306", None, "test", 1, app)
    #print(t.configure())
    #print(t.upload())
    print(t.configure2(app))
    print(t.phaseOne(60, True, False))
    print(t.phaseTwo(60, True))
    print(t.analysis())
    print(t.result())
    #time.sleep(5)
    #print(t.sanitize())

def virtualtest(app):
    t = Traffic("192.168.1.201", "400", "192.168.3.17", None, "virt_test ", 1, None)
    # print(t.configure())
    # print(t.upload())
    print(t.configure2(app))
    print(t.phaseOne(30, True, False))
    print(t.phaseTwo(30, True))
    print(t.analysis())
    print(t.result())
# aee4ad920306
# 3d3799289906
# 50918aee9906
# manualPhaseTwo("com.cardinalblue.piccollage.google")
# manualPhaseOne('com.blyts.chinchon')
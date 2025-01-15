from datetime import datetime
import os

aapt = "/usr/bin/aapt"

def log(tag, message):
    utc_time = datetime.utcnow()
    utc_str = utc_time.strftime('%Y-%m-%d-%H:%M:%S')



#########################################################3
#                         AAPT WRAPPERS                 #
##########################################################
import subprocess


def aapt_call(command, args):
    global aapt

    assert aapt is not None, 'SDK configuration not yet initialized, need to init() first'
    aapt_cmd = [aapt, command]
    aapt_cmd.extend(args)
    log('AAPT', aapt_cmd)
    result = None
    try:
        result = subprocess.check_output(aapt_cmd, stderr=subprocess.STDOUT).decode('UTF-8', 'backslashreplace')
    except Exception as e:
        log('AAPT-ERROR', str(e))
    finally:
        return result


last_badging_apk = None
last_badging = None


def aapt_badging(apk_file):
    global last_badging_apk, last_badging
    if last_badging_apk is None or apk_file != last_badging_apk:
        last_badging = aapt_call('d', ['badging', apk_file])
        last_badging_apk = apk_file
    return last_badging


def aapt_permissions(apk_file):
    assert os.path.isfile(apk_file), '%s is not a valid APK path' % apk_file
    output = aapt_badging(apk_file)
    permissions = []
    if output is not None:
        lines = output.split('\n')
        permissions = [x.split('name=')[1].strip("'") for x in lines if x.startswith('uses-permission:')]

    return permissions


def aapt_package(apk_file):
    assert os.path.isfile(apk_file), '%s is not a valid APK path' % apk_file
    output = aapt_badging(apk_file)
    package = None
    if output is not None:
        lines = output.split('\n')
        package = [x for x in lines if x.startswith('package: name=')]
        assert len(package) == 1, 'More than one aapt d badging line starts with "package: name="'
        package = package[0].split('name=')[1].split(' versionCode=')[0].strip("'")
    return package


def aapt_version_code(apk_file):
    assert os.path.isfile(apk_file), '%s is not a valid APK path' % apk_file
    output = aapt_badging(apk_file)
    version_code = None
    if output is not None:
        lines = output.split('\n')
        package = [x for x in lines if x.startswith('package: name=')]
        assert len(package) == 1, 'More than one aapt d badging line starts with "package: name="'
        version_code = package[0].split('versionCode=')[1].split(' versionName=')[0].strip("'")

    return version_code

##########################################################################
#                          ADB and AAPT WRAPPERS                         #
##########################################################################
import os
import configparser
import multiprocessing
import time
from datetime import datetime, timedelta
import subprocess
import random
import sys

adb = None
aapt = None

device_serial = None


def log(tag, message):
    utc_time = datetime.utcnow()
    utc_str = utc_time.strftime('%Y-%m-%d-%H:%M:%S')

    print('(%s) %s -- %s' % (tag, utc_str, message))


def parse_config(config_file):
    assert os.path.isfile(config_file), '%s is not a valid file or path to file' % config_file

    config = configparser.ConfigParser()
    config.read(config_file)

    assert 'sdk' in config.sections(), 'Config file %s does not contain an sdk section' % config_file
    assert 'ADBPath' in config['sdk'], 'Config file %s does not have an ADBPath value in the sdk section' % config_file
    assert 'AAPTPath' in config[
        'sdk'], 'Config file %s does not have an AAPTPath value in the sdk seciton' % config_file

    adb_path = config['sdk']['ADBPath']
    aapt_path = config['sdk']['AAPTPath']

    assert os.path.isfile(adb_path), 'adb binary not found in %s' % adb_path
    assert os.path.isfile(aapt_path), 'aapt binary not found in %s' % aapt_path

    global adb, aapt
    adb = adb_path
    aapt = aapt_path


def init(config_file, device=None):
    parse_config(config_file)

    global device_serial
    if device is not None and len(device) > 0:
        device_serial = device
    else:
        (success, device_serial) = adb_shell('getprop ro.serialno')
        assert success, 'Unable to get device serial number through adb getprop ro.serialno'
    device_serial = device_serial.lower().strip()


#########################################################3
#                         AAPT WRAPPERS                 #
##########################################################


def aapt_call(command, args):
    global aapt

    assert aapt is not None, 'SDK configuration not yet initialized, need to init() first'
    aapt_cmd = [aapt, command]
    aapt_cmd.extend(args)
    log('AAPT', aapt_cmd)
    result = None
    try:
        result =  subprocess.check_output(aapt_cmd, stderr=subprocess.STDOUT).decode('UTF-8', 'backslashreplace')
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


###########################
#        ADB WRAPPERS     #
###########################

def adb_call(command, args=None, ret_queue=None):
    global adb, device_serial

    assert adb is not None, 'ADB configuration not yet initialized, need to init() first'
    adb_cmd = [adb, '-s', device_serial, command] if device_serial is not None else [adb, command]
    if args is not None:
        adb_cmd.extend(args)
    log('ADB', str(adb_cmd))
    result = None
    success = True
    try:
        result = subprocess.check_output(adb_cmd, stderr=subprocess.STDOUT).decode('UTF-8', 'backslashreplace')
    except Exception as e:
        # print(str(e))
        result = str(e)  # e.output.decode('UTF-8', 'backslashreplace')
        success = False

    if ret_queue is not None:
        ret_queue.put('{}:{}'.format(success, result))

    return success, result


def adb_call_timeout(command, args, timeout_secs=90, quit_on_fail=False):
    ret = multiprocessing.Queue()
    proc = multiprocessing.Process(target=adb_call, args=(command, args), kwargs={'ret_queue': ret})
    log('ADB', 'Starting command "%s" with timeout %d' % (command, timeout_secs))
    proc.start()

    end_time = datetime.now() + timedelta(seconds=timeout_secs)
    success = True
    while proc.is_alive():
        time.sleep(2)
        if datetime.now() > end_time:
            log('ADB', 'Command "%s" timed out' % command)

            proc.terminate()
            proc.join()

            success = False

    log('ADB', 'Command "%s" terminated' % command)

    if not success and quit_on_fail:
        log('CRASH', 'Failed on command "%s", rebooting' % command)
        sys.exit(1)

    if success:
        out = ret.get_nowait().split(':')
        success = True if out[0] == "True" else False
        return success, out[1]
    else:
        return success, None


def adb_shell(args, timeout_secs=10, retry_limit=3):
    (success, ret) = adb_call_timeout('shell', args, timeout_secs=timeout_secs)

    while not success and retry_limit > 0:
        (success, ret) = adb_call_timeout('shell', args, timeout_secs=timeout_secs)
        retry_limit = retry_limit - 1

    return success, ret


def adb_shutdown():
    adb_shell(['reboot', ' -p'])


def adb_isconnected():
    global device_serial
    (success, result) = adb_call('devices')
    if result is not None:
        device_found = result.lower().find(device_serial) >= 0
    else:
        device_found = None
    return device_found


def adb_isbooted():
    (success, result) = adb_shell(['getprop', ' sys.boot_completed'])

    return success and result.strip() == '1'


def adb_wait_boot(timeout_secs=240):
    end_time = datetime.now() + timedelta(seconds=timeout_secs)

    log('WAITBOOT', 'Checking if device is booted')

    while (not (adb_isconnected() and adb_isbooted())):
        # Re-issue the reboot command if it's taking too long
        if (datetime.now() > end_time and adb_isconnected()):
            log('REBOOT', 'Retrying reboot after taking longer than %d seconds' % timeout_secs)
            adb_shell(['reboot'])
            end_time = datetime.now() + timedelta(seconds=timeout_secs)

        time.sleep(2)

    log('WAITBOOT', 'Device is booted')


def adb_reboot(wait=False, unlock=False, password=None):
    log('REBOOT', 'Reboot device')
    adb_shell(['reboot'])

    if wait:
        adb_wait_boot()
        if unlock and password is not None:
            adb_shell(['input touchscreen swipe 930 880 930 380'], retry_limit=0)
            adb_shell(['input text {}'.format(password)], retry_limit=0)
            adb_shell(['input tap 855 988'], retry_limit=0)

def adb_grant_permission(apk_file):
    assert os.path.isfile(apk_file), '%s is not a valid APK path'

    log('GRANT_PERM', 'Calling aapt on %s' % apk_file)
    package = aapt_package(apk_file)
    log('GRANT_PERM', 'Granting all permissions %s' % package)
    permissions = aapt_permissions(apk_file)
    permissions_nogranted = []
    for perm in permissions:
        try:
            adb_shell(['pm', 'grant', package, perm], retry_limit=0)
        except subprocess.CalledProcessError as e:
            # Ignore error raised by trying to turn on non-toggleable permissions
            print(e.output.decode('UTF-8', 'backslashreplace'))
            permissions_nogranted.append(perm)
            continue
    return permissions, permissions_nogranted


def adb_install(apk_file, grant_all_perms=False):
    assert os.path.isfile(apk_file), '%s is not a valid APK path'

    log('INSTALL', 'Calling aapt on %s' % apk_file)
    package = aapt_package(apk_file)
    log('INSTALL', 'Installing %s' % package)
    (success, output) = adb_call_timeout('install', ['-r', apk_file], timeout_secs=60)
    installed = adb_package_installed(package)
    if not installed:
        if grant_all_perms:
            return (False, output, None, None)
        else:
            return (False, output)
    if installed and grant_all_perms:
        success = True
        (permissions, permissions_nogranted) = adb_grant_permission(apk_file)
        return success, output, permissions, permissions_nogranted
    return success, output


def adb_install_auto(apk_file, grant_all_perms=False, timeout_secs=90, quit_on_fail=False):
    ret = multiprocessing.Queue()
    proc = multiprocessing.Process(target=adb_call, args=('install', ['-r', apk_file]), kwargs={'ret_queue': ret})
    log('INSTALL', 'Calling aapt on %s' % apk_file)
    package = aapt_package(apk_file)
    log('INSTALL', 'Installing %s with timeout %d' % (package, timeout_secs))
    proc.start()

    end_time = datetime.now() + timedelta(seconds=timeout_secs)
    success = True
    while proc.is_alive() and not adb_package_installed(package):
        time.sleep(4)
        # adb_shell(['input tap 391 1960'], retry_limit=0)  # this is for the first phone Xiaomi XYZ
        adb_shell(['input tap 201 1270'], retry_limit=0)  # This is for redmi 7a

        if datetime.now() > end_time:
            log('ADB', 'Install "%s" timed out' % package)
            proc.terminate()
            proc.join()
            success = False
    installed = adb_package_installed(package)
    if not installed:
        if grant_all_perms:
            return (False, None, None, None)
        else:
            return (False, None)
    if installed and grant_all_perms:
        success = True
        (permissions, permissions_nogranted) = adb_grant_permission(apk_file)
        return success, None, permissions, permissions_nogranted
    return success, None


def adb_start_app(package):
    # Always start from the home screen
    adb_shell(['input', 'keyevent', '3'])
    time.sleep(2)
    (success, output) = adb_shell(['monkey', '-p', package, '-c', 'android.intent.category.LAUNCHER', '1'])
    return (success, output)


def adb_package_installed(package):
    (success, output) = adb_shell(['pm', 'list packages', package])
    return success and len(output) > 0


def adb_clear_screen():
    # Just bang on the "enter" button from the Home Screen a bunch of times
    adb_shell(['input keyevent 3'])
    time.sleep(2)

    for n in range(10):
        adb_shell(['input keyevent 66'])
        time.sleep(1)

    adb_shell(['input keyevent 3'])
    time.sleep(2)


def adb_is_wifi_connected(enable_wifi=False):
    if (enable_wifi):
        adb_shell(['svc wifi enable'])  # Ensure wi-fi is on before checking
        time.sleep(20)

    (success, result) = adb_shell(["dumpsys wifi | grep 'mNetworkInfo' | cut -d ',' -f2 | cut -d '/' -f2"])
    return success and result.strip() == 'CONNECTED'


def adb_is_screen_on():
    (success, result) = adb_shell(["dumpsys power | grep 'Display Power' | cut -d'=' -f2"])
    return success and result.strip() == 'ON'


def adb_screen_turn_on():
    if not adb_is_screen_on():
        adb_shell(['input keyevent 26'])


def adb_screen_turn_off():
    if adb_is_screen_on():
        adb_shell(['input keyevent 26'])

def adb_is_unlocked():
    (success, result) = adb_shell(["dumpsys power | grep 'mHoldingDisp' | cut -d'=' -f2"])
    return success and result.strip() == 'true'


def adb_unlock(password):
    if not adb_is_screen_on():
        adb_screen_turn_on()
    adb_shell(['input touchscreen swipe 930 880 930 380'], retry_limit=0)
    adb_shell(['input text {}'.format(password)], retry_limit=0)
    adb_shell(['input tap 855 988'], retry_limit=0)

def adb_screenshot(out_file):
    log('SCREENSHOT', 'Screenshot %s' % out_file)
    screen_tmp = '/sdcard/int-transfer.png.tmp'

    (success, ret) = adb_shell(['screencap', '-p', screen_tmp])
    if success:
        adb_call_timeout('pull', [screen_tmp, out_file], timeout_secs=10)
        adb_shell(['rm %s' % screen_tmp])


def adb_is_portrait():
    (success, result) = adb_shell(['dumpsys input | grep SurfaceOrientation'])
    return success and result.strip().endswith('0')


def adb_monkey(package, seed=None, delay_ms=1000, event_count=100, pct_trackball=0, pct_nav=0, pct_majornav=0,
               pct_syskeys=0, pct_flip=0, pct_anyevent=0):
    seed = seed if seed is not None else random.randrange(999999999999)

    log('MONKEY', 'Seed=%d' % seed)
    log('MONKEY', 'DelayMS=%d' % delay_ms)
    log('MONKEY', 'EventCount=%d' % event_count)

    monkey_args = 'monkey \
                   -s %d \
                   -p %s \
                   --throttle %s \
                   --pct-trackball %d \
                   --pct-nav %d \
                   --pct-majornav %d \
                   --pct-syskeys %d \
                   --pct-flip %d \
                   --pct-anyevent %d  \
                   --ignore-crashes --ignore-timeouts --ignore-security-exceptions -v %d' % \
                  (seed, package, delay_ms, pct_trackball, pct_nav, pct_majornav, pct_syskeys, pct_flip, pct_anyevent,
                   event_count)
    adb_shell([monkey_args], timeout_secs=120, retry_limit=0)


##################################3
#            OTHER CALLS          #
###################################

def call_sh(command, timeout_secs=10):
    result = None
    success = True
    try:
        result = subprocess.run(command, timeout=timeout_secs, shell=True, check=True, stderr=subprocess.STDOUT)
        print(result.stderr)
    except Exception as e:
        result = str(e)
        success = False
    return (success, result)


def call_sh_output(command, timeout_secs=10):
    result = None
    success = True
    try:
        result = subprocess.run(command, timeout=timeout_secs, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        print(result.stdout)
    except Exception as e:
        result = str(e)
        success = False
    return (success, result)


#init('/app/scripts/testing.config', '4fa3f19c')
# print(adb_install('/home/privapp/app/logs/apk/kahoot.apk', True))
# print (adb_start_app('no.mobitroll.kahoot.android'))
# print (adb_package_installed('no.mobitroll.kahoot.android'))
# print (adb_clear_screen())
# print (adb_is_wifi_connected())
# print(adb_is_screen_on())
# adb_screen_turn_on()
# print(adb_is_portrait())
# adb_monkey("no.mrobitroll.kahoot.android")
# call_sh_background('nohup mitmdump -s intercept/inspect_requests.py --set app=pp')
# adb_install_auto('/app/base.apk', grant_all_perms=True, timeout_secs=90, quit_on_fail=False)
# print(call_sh('nohup mitmdump -s intercept/inspect_requests.py --set app=no.mobitroll.kahoot.android &'))
# print(call_sh('nohup /app/intercept/pinning/fridactl.py 4fa3f19c no.mobitroll.kahoot.android  &'))
# adb_screen_turn_on()
# adb_reboot(True)
# time.sleep(3)
# adb_shell(['input keyevent 26'], retry_limit=0)
# adb_shell(['input touchscreen swipe 930 880 930 380'], retry_limit=0)
# adb_shell(['input text 5131'], retry_limit=0)
# adb_shell(['input keyevent 66'], retry_limit=0)
#adb_call("install", ['r-', 'base.apk'])

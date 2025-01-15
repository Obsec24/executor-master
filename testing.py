import configparser

import traffico as tr
import time
import os
import sys

BASE_PATH = None
TESTING_SERVER_IP = None
TESTING_SERVER_PORT = None
TESTING_DEVICE = None
PHASE_ONE_TIMEOUT = 10
PERMISSIONS = True
REBOOT = False

PHASE_TWO_TIMEOUT = 10
MONKEY = True
logger = None
RESULTS_OUTPUT = None

TESTING_LABEL = None
TIMEOUT_BEFORE_SANITIZATION = 20

SUCCESS = 0
SOFT_FAIL = 1
HARD_FAIL = 2
DEVICE_NOT_CONNECTED_ERROR = 10
APP_INSTALL_FAIL_ERROR = 20
MITM_PROXY_START_ERROR = 30
SERVER_CONNECTION_ERROR = 40

CONTAINER = 'traffic'

def parse_config(config_file):
    global BASE_PATH, TESTING_SERVER_IP, TESTING_SERVER_PORT, \
        TESTING_DEVICE, RESULTS_OUTPUT, PHASE_ONE_TIMEOUT, PHASE_TWO_TIMEOUT, PERMISSIONS, REBOOT, \
        MONKEY, TESTING_LABEL

    config = configparser.ConfigParser()
    config.read(config_file)

    BASE_PATH = config['base']['base_path']
    RESULTS_OUTPUT = config['base']['results_output']

    TESTING_SERVER_IP = config['testing_env']['testing_server_ip']
    TESTING_SERVER_PORT = config['testing_env']['testing_server_port']
    TESTING_DEVICE = config['testing_env']['testing_terminal']
    PHASE_ONE_TIMEOUT = int(config['testing']['phase-one_timeout'])
    PHASE_TWO_TIMEOUT = int(config['testing']['phase-two_timeout'])
    PERMISSIONS = True if config['testing']['permissions'] == "True" else False
    REBOOT = True if config['testing']['reboot'] == "True" else False
    MONKEY = True if config['testing']['monkey'] == "True" else False
    TESTING_LABEL = config['testing']['testing_label']


def traffic_testing(apk, version, app, logger_in):
    global RESULTS_OUTPUT, logger
    logger = logger_in
    cwd = os.path.dirname(os.path.abspath(sys.argv[0]))
    parse_config(os.path.join(cwd, 'executor.config'))
    if not os.path.isfile(apk):
        logger.error('APK traffic analysis failed', extra={'reason': 'Invalid APK path', 'apk': app, 'version': version, 'container': CONTAINER})
        return HARD_FAIL
    # data_dir = os.path.join(RESULTS_OUTPUT, app, version)
    # if not os.path.isdir(data_dir):
    #     os.makedirs(data_dir)
    # data_dir = os.path.join(data_dir, 'testing-%s' % TESTING_LABEL)
    # if not os.path.isdir(data_dir):
    #     os.makedirs(data_dir)

    t = tr.Traffic(TESTING_SERVER_IP, TESTING_SERVER_PORT, TESTING_DEVICE, apk, TESTING_LABEL, version, app)
    (success, result) = t.configure()
    if not success:
        logger.error('APK traffic analysis failed', extra={'reason': 'App to be tested and testing terminal setup failed',
                                                             'apk': app, 'version': version,
                                                             'testing_label': TESTING_LABEL,
                                                             'container': CONTAINER,
                                                             'exception_message': result,
                                                             'device': TESTING_DEVICE})
        return HARD_FAIL
    else:
        logger.debug('App to be tested and testing terminal have been setup', extra={'apk': app, 'version': version,
                                                           'testing_label': TESTING_LABEL,
                                                           'container': CONTAINER,
                                                           'device': TESTING_DEVICE})
    (success, result) = t.upload()
    if not success:
        logger.error('APK traffic analysis failed', extra={'reason': 'Application upload failed',
                                                           'apk': app, 'version': version, 'container': CONTAINER,
                                                           'testing_label': TESTING_LABEL,'exception_message': result,
                                                           'device': TESTING_DEVICE})
        return HARD_FAIL
    else:
        logger.debug('App to be evaluated has been uploaded', extra={'apk': app, 'version': version,
                                                                                    'testing_label': TESTING_LABEL,
                                                                                    'container': CONTAINER,
                                                                                    'device': TESTING_DEVICE})
    (success, result, code) = t.phaseOne(timeout=PHASE_ONE_TIMEOUT, permissions=PERMISSIONS, reboot=REBOOT)
    if not success:
        if code == DEVICE_NOT_CONNECTED_ERROR:
            reason = 'Device is not connected'
        elif code == MITM_PROXY_START_ERROR:
            reason = 'Mitm proxy start failed'
        elif code == APP_INSTALL_FAIL_ERROR:
            reason = 'App installation failed'
        elif code == SERVER_CONNECTION_ERROR:
            reason = 'Connection to REST server failed'
        else:
            reason = 'Unknown failure during idle traffic capture'
        logger.error('APK traffic analysis failed', extra={'reason': reason,
                                                             'apk': app, 'version': version, 'container': CONTAINER,
                                                             'testing_label': TESTING_LABEL, 'exception_message': result,
                                                             'exitcode': code, 'device': TESTING_DEVICE})
        if code == DEVICE_NOT_CONNECTED_ERROR or code == MITM_PROXY_START_ERROR or code == SERVER_CONNECTION_ERROR:
            return HARD_FAIL
        else:
            return SOFT_FAIL
    else:
        logger.debug('Idle phase traffic has been captured', extra={'apk': app, 'version': version,
                                                                     'testing_label': TESTING_LABEL,
                                                                     'container': CONTAINER,
                                                                     'device': TESTING_DEVICE})
    (success, result, code) = t.phaseTwo(timeout=PHASE_TWO_TIMEOUT, monkey=MONKEY)
    if not success:
        logger.error('Second phase traffic capture failed', extra={'reason': 'REST-Phase-Two request failed',
                                                             'apk': app, 'version': version, 'container': CONTAINER,
                                                             'testing_label': TESTING_LABEL, 'exception_message': result,
                                                             'exitcode': code, 'device': TESTING_DEVICE})
    else:
        logger.debug('Second phase traffic has been captured', extra={'apk': app, 'version': version,
                                                                     'testing_label': TESTING_LABEL,
                                                                     'container': CONTAINER,
                                                                     'device': TESTING_DEVICE})
    (success, result) = t.analysis()
    if not success:
        logger.error('APK traffic analysis failed', extra={'reason': 'The analysis of captured traffic failed',
                                                            'apk': app, 'version': version, 'container': CONTAINER,
                                                            'testing_label': TESTING_LABEL, 'exception_message': result,
                                                            'device': TESTING_DEVICE})
    else:
        logger.debug('Captured traffic has been analysed', extra={'apk': app, 'version': version,
                                                                     'testing_label': TESTING_LABEL,
                                                                     'container': CONTAINER,
                                                                     'device': TESTING_DEVICE})
    (success, result) = t.result()
    if not success:
        logger.error('Reading results failed', extra={'reason': 'REST-Reading-results request failed',
                                                                   'apk': app, 'version': version,
                                                                   'container': CONTAINER,
                                                                   'testing_label': TESTING_LABEL,
                                                                   'exception_message': result,
                                                                   'device': TESTING_DEVICE})
    else:
        print(result)
    '''(success, result) = t.screenshotPhaseOne(RESULTS_OUTPUT)
    if not success:
        logger.error('Error Reading screenshots Phase One : {} -> {}'.format(name, result))
    (success, result) = t.screenshotPhaseTwo(RESULTS_OUTPUT)
    if not success:
        logger.error('Error Reading screenshots Phase Two : {} -> {}'.format(name, result))'''
    # (success, result) = t.rawPhaseOne(data_dir)
    # if not success:
    #     logger.error('Error Reading Raw Data Phase One : {} -> {}'.format(name, result))
    # (success, result) = t.rawPhaseTwo(data_dir)
    # if not success:
    #     logger.error('Error Reading Raw Data Phase Two : {} -> {}'.format(name, result))
    time.sleep(TIMEOUT_BEFORE_SANITIZATION)
    t.sanitize()
    logger.info('APK traffic analysis has been completed', extra={'apk': app, 'version': version, 'testing_label': TESTING_LABEL,
                                              'container': CONTAINER, 'device': TESTING_DEVICE})
    return SUCCESS

# test
# traffic_testing('/privapp/apk/com.netflix.Speedtest.apk')

#!/usr/bin/env python3
import pika
import sys
import functools
import os
import importlib
import testing as t
import threading
import configparser
import apistorage as st
import json
from datetime import datetime, timedelta
import tools
import subprocess

BASE_PATH = None
FILE_LOGS = None
HELPER_JSON_LOGGER = None
logger = None

RABBIT_PASSWORD = None
RABBIT_USERNAME = None
RABBIT_SERVER = None
RABBIT_PORT = None
RABBIT_QUEUE = None
RABBIT_EXCHANGE = None

STORAGE_SERVER = None
STORAGE_PORT = None

TESTING_LABEL = None
CONTAINER = 'traffic'

TOOLS_FILE = '/app/scripts/testing.config'
DEVICE = None
REBOOT_TIMEOUT = 3600
FORCE_REBOOT = True
end_time = 0

SUCCESS = 0
SOFT_FAIL = 1
HARD_FAIL = 2

ABNORMAL_SOFT_THRESHOLD = 3
abnormal_soft_count = 0
N_DEVICES = 5


def parse_config(config_file):
    global BASE_PATH, FILE_LOGS, HELPER_JSON_LOGGER, logger, RABBIT_PASSWORD, RABBIT_USERNAME, \
        RABBIT_EXCHANGE, RABBIT_QUEUE, RABBIT_SERVER, RABBIT_PORT, STORAGE_SERVER, STORAGE_PORT, \
        TESTING_LABEL, DEVICE, FORCE_REBOOT, REBOOT_TIMEOUT, ABNORMAL_SOFT_THRESHOLD, end_time

    config = configparser.ConfigParser()
    config.read(config_file)

    BASE_PATH = config['base']['base_path']
    assert os.path.isdir(BASE_PATH), 'directory %s not valid' % BASE_PATH
    FILE_LOGS = os.path.join(BASE_PATH, 'logging/log/executor.privapp.log')
    HELPER_JSON_LOGGER = os.path.join(BASE_PATH, 'logging/agent/helper/log.py')

    # configure json logger
    log = importlib.import_module('log', HELPER_JSON_LOGGER)
    logger = log.init_logger(FILE_LOGS)

    RABBIT_PASSWORD = config['rabbitmq']['password']
    RABBIT_USERNAME = config['rabbitmq']['username']
    RABBIT_SERVER = config['rabbitmq']['server_ip']
    RABBIT_PORT = config['rabbitmq']['server_port']
    RABBIT_QUEUE = config['rabbitmq']['queue']
    RABBIT_EXCHANGE = config['rabbitmq']['exchange']
    STORAGE_SERVER = config['storage']['ip']
    STORAGE_PORT = config['storage']['port']
    TESTING_LABEL = config['testing']['testing_label']
    # these were used to reboot devices after REBOOT_TIMEOUT seconds. In order to avoid restarting all devices
    # at the same time, we added an offset
    DEVICE = config['testing_env']['testing_terminal']
    FORCE_REBOOT = True if config['testing_env']['force_reboot'] == "True" else False
    REBOOT_TIMEOUT = int(config['testing_env']['reboot_timeout'])
    ABNORMAL_SOFT_THRESHOLD = int(config['testing_env']['abnormal_threshold'])
    offset = int(config['testing_env']['testing_server_port'][-1])
    end_time = datetime.now() + timedelta(seconds=REBOOT_TIMEOUT) + timedelta(
        seconds=offset * REBOOT_TIMEOUT / (N_DEVICES + 1))


def ack_message(channel, delivery_tag):
    if channel.is_open:
        channel.basic_ack(delivery_tag)
    else:
        logger.error("Ack cannot be delivered!")


def call_sh(command):
    success = True
    try:
        result = subprocess.call(command, shell=True)
    except Exception as e:
        result = str(e)
        success = False
    return success, result


def testing(connection, channel, delivery_tag, body):
    global abnormal_soft_count, end_time, DEVICE, TOOLS_FILE, FORCE_REBOOT
    print(" [x] Received {}".format(body.decode('utf-8')))
    print(" [x] Started app analysis {}".format(body.decode('utf-8')))

    body_json = json.loads(body)
    app = body_json['apk']
    version = body_json['version']
    storage = st.Storage(STORAGE_SERVER, STORAGE_PORT, app, version)
    code, value = storage.apk('.')
    if code == SUCCESS:
        apk_path = value
        logger.debug("Apk recovered from the Storage server", extra={'apk': app, 'version': version,
                                                                     'testing_label': TESTING_LABEL,
                                                                     'container': CONTAINER, 'device': DEVICE})
        exit_code = t.traffic_testing(apk_path, str(version), app, logger)
        if exit_code == SOFT_FAIL:
            abnormal_soft_count += 1
        elif exit_code == SUCCESS:
            abnormal_soft_count = 0
        os.remove(apk_path)

        if exit_code == SUCCESS or (exit_code == SOFT_FAIL and abnormal_soft_count < ABNORMAL_SOFT_THRESHOLD):
            cb = functools.partial(ack_message, channel, delivery_tag)
            connection.add_callback_threadsafe(cb)
            logger.debug(" App removed from queue", extra={'apk': app, 'version': version, 'container': CONTAINER,
                                                           'testing_label': TESTING_LABEL, 'device': DEVICE})
            if FORCE_REBOOT and datetime.now() > end_time:
                logger.debug("Rebooting device",
                             extra={'reason': 'Scheduled device reboot', 'apk': app, 'version': version,
                                    'container': CONTAINER,
                                    'testing_label': TESTING_LABEL, 'device': DEVICE})
                tools.init(TOOLS_FILE, DEVICE)
                tools.adb_reboot(wait=False, unlock=False)
        else:
            logger.error("Critical state, locking out rabbit ACK!",
                         extra={'reason': 'Device not connected or multiple app installation failed', 'apk': app, 'version': version,
                                'container': CONTAINER, 'testing_label': TESTING_LABEL,
                                'device': DEVICE})
    elif code == SOFT_FAIL:
        logger.error("Couldn't get the apk from the Storage server", extra={'exception_message': value,
                                                                            'apk': app, 'version': version,
                                                                            'testing_label': TESTING_LABEL,
                                                                            'container': CONTAINER, 'device': DEVICE})
        cb = functools.partial(ack_message, channel, delivery_tag)
        connection.add_callback_threadsafe(cb)
        logger.debug(" App removed from queue", extra={'apk': app, 'version': version, 'container': CONTAINER,
                                                       'testing_label': TESTING_LABEL, 'device': DEVICE})
    else:  # RabbitMQ will be locked in, as the storage server is not responding
        logger.error("Storage server is not responding!", extra={'exception_message': value,
                                                                 'apk': app, 'version': version,
                                                                 'testing_label': TESTING_LABEL,
                                                                 'container': CONTAINER})


def on_message(channel, method_frame, header_frame, body, args):
    (connection, threads) = args
    delivery_tag = method_frame.delivery_tag
    th = threading.Thread(target=testing, args=(connection, channel, delivery_tag, body))
    th.start()
    threads.append(th)


if __name__ == '__main__':
    cwd = os.path.dirname(os.path.abspath(sys.argv[0]))
    parse_config(os.path.join(cwd, 'executor.config'))
    # starting logging agent
    (success, result) = call_sh('service filebeat start')
    if not success:
        logger.error('Filebeat agent start failed', extra={'exception_message': result, 'testing_label': TESTING_LABEL,
                                                           'container': CONTAINER})
    else:
        logger.debug('Filebeat agent started successfully', extra={'testing_label': TESTING_LABEL,
                                                                   'container': CONTAINER})
    logger.debug('Starting traffic analysis module', extra={'testing_label': TESTING_LABEL,
                                                            'container': CONTAINER})

    credentials = pika.PlainCredentials(RABBIT_USERNAME, RABBIT_PASSWORD)
    parameters = pika.ConnectionParameters(RABBIT_SERVER, RABBIT_PORT, credentials=credentials, heartbeat=5)
    connection = pika.BlockingConnection(parameters)

    channel = connection.channel()
    channel.exchange_declare(exchange=RABBIT_EXCHANGE, exchange_type="fanout", passive=False, durable=True,
                             auto_delete=False)
    result = channel.queue_declare(queue=RABBIT_QUEUE, durable=True, auto_delete=False,
                                   arguments={"x-queue-type": "quorum"})
    channel.queue_bind(queue=result.method.queue, exchange=RABBIT_EXCHANGE)

    channel.basic_qos(prefetch_count=1)

    threads = []
    on_message_callback = functools.partial(on_message, args=(connection, threads))
    channel.basic_consume(on_message_callback=on_message_callback, queue=result.method.queue)

    print(' [*] Waiting for messages. To exit press CTRL+C')

    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()

    for thread in threads:
        thread.join()
    connection.close()

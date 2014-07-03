#!/usr/bin/env python
'''
Created on Aug 1, 2012

@author: negronjl
'''

import commands
import os
import re
import signal
import socket
import subprocess
import sys
import time
import yaml

from os import chmod
from os import remove
from os.path import exists
from string import Template
from textwrap import dedent
from yaml.constructor import ConstructorError

from charmhelpers.fetch import (
    add_source,
    apt_update,
    apt_install
)

from charmhelpers.core.hookenv import (
    config,
    unit_get,
    relation_get,
    relation_set,
    relations_of_type,
    open_port,
    close_port,
    Hooks,
)

from charmhelpers.core.hookenv import log as juju_log

from charmhelpers.core.host import (
    service,
)

hooks = Hooks()

###############################################################################
# Global variables
###############################################################################
default_mongodb_config = "/etc/mongodb.conf"
default_mongodb_init_config = "/etc/init/mongodb.conf"
default_mongos_list = "/etc/mongos.list"
default_wait_for = 10
default_max_tries = 5

###############################################################################
# Supporting functions
###############################################################################

def port_check(host=None, port=None, protocol='TCP'):
    if host is None or port is None:
        juju_log("port_check: host and port must be defined.")
        return(False)
    if protocol.upper() == 'TCP':
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif protocol.upper() == 'UDP':
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        juju_log("port_check: Unrecognized protocol %s" % protocol)
        return(False)
    try:
        s.connect((host, int(port)))
        s.shutdown(socket.SHUT_RDWR)
        juju_log("port_check: %s:%s/%s is open" % (host, port, protocol))
        return(True)
    except Exception, e:
        juju_log("port_check: Unable to connect to %s:%s/%s." %
        (host, port, protocol))
        juju_log("port_check: Exception: %s" % str(e))
        return(False)


#------------------------------------------------------------------------------
# update_service_ports:  Convenience function that evaluate the old and new
#                        service ports to decide which ports need to be
#                        opened and which to close
#------------------------------------------------------------------------------
def update_service_ports(old_service_ports=None, new_service_ports=None):
    juju_log("update_service_ports")
    if old_service_ports is None or new_service_ports is None:
        return(None)
    for port in old_service_ports:
        if port not in new_service_ports:
            juju_log("closing port: %d" % int(port))
            close_port(port)
    for port in new_service_ports:
        if port not in old_service_ports:
            juju_log("opening port: %d" % int(port))
            open_port(port)


def regex_sub(pat_replace=None, data=None):
    juju_log("regex_sub")
    if not pat_replace or not data:
        raise Exception("pat_replace or data not defined")
    if not isinstance(pat_replace, list):
        raise Exception("pat_replace must be a list of pat, replace tuples")
    new_data = data
    for (pattern, replace) in pat_replace:
        new_data = re.sub(pattern, replace, data, 0, re.MULTILINE)
    return(new_data)


def update_file(filename=None, new_data=None, old_data=None):
    juju_log("update_file: %s" % filename)
    if filename is None or new_data is None:
        retVal = False
    try:
        if old_data != new_data:
            with open(filename, 'w') as f:
                f.write(new_data)
        retVal = True
    except Exception, e:
        juju_log(str(e))
        retVal = False
    finally:
        juju_log("update_file %s returns: %s" % (filename, retVal))
        return(retVal)


def process_check(pid=None):
    try:
        if pid is not None:
            cmd_line = subprocess.check_output('ps -p %d -o cmd h' %
            int(pid), shell=True)
            retVal = (pid, cmd_line)
        else:
            juju_log("process_check: pid not defined.")
            retVal = (None, None)
    except Exception, e:
        juju_log("process_check exception: %s" % str(e))
        retVal = (None, None)
    finally:
        juju_log("process_check returs pid: %s and cmd_line: %s" %
        retVal)
        return(retVal)


def process_check_pidfile(pidfile=None):
    if pidfile is not None and os.path.exists(pidfile):
        return(process_check(open(pidfile).read()))
    else:
        juju_log("process_check_pidfile: undefined or non-existant pidfile.")
        return((None, None))




###############################################################################
# Charm support functions
###############################################################################
def mongodb_conf(config_data=None):
    if config_data is None:
        return(None)
    config = []

    # header
    config.append("# mongodb.conf")
    config.append("")

    # dbpath
    # Create the directory if not there already
    subprocess.call(['mkdir', '-p', '%s' % config_data['dbpath']])
    # Make sure the mongodb user has access to it
    subprocess.call(['chown', '-R', 'mongodb:mongodb', config_data['dbpath']])
    config.append("dbpath=%s" % config_data['dbpath'])
    config.append("")

    # logpath
    # Create the directory if not there already
    subprocess.call(['mkdir',
        '-p',
        '%s' % os.path.dirname(config_data['logpath'])])
    subprocess.call(['chown',
        '-R',
        'mongodb:mongodb', os.path.dirname(config_data['logpath'])])
    config.append("logpath=%s" % config_data['logpath'])
    config.append("")

    # log_append
    if config_data['logappend']:
        config.append("logappend=true")
        config.append("")

    # bind_ip
    if config_data['bind_ip'] != "all":
        config.append("bind_ip = %s" % config_data['bind_ip'])
        config.append("")

    # port
    config.append("port = %d" % config_data['port'])
    config.append("")

    # journal
    if config_data['journal']:
        config.append("journal=true")
        config.append("")

    # cpu
    if config_data['cpu']:
        config.append("cpu = true")
        config.append("")

    # auth
    if config_data['auth']:
        config.append("auth = true")
        config.append("")

    # verbose
    if config_data['verbose']:
        config.append("verbose = true")
        config.append("")

    # objcheck
    if config_data['objcheck']:
        config.append("objcheck = true")
        config.append("")

    # quota
    if config_data['quota']:
        config.append("quota = true")
        config.append("")

    # diaglog
    config.append("diaglog = %d" % config_data['diaglog'])
    config.append("")

    # nocursors
    if config_data['nocursors']:
        config.append("nocursors = true")
        config.append("")

    # nohints
    if config_data['nohints']:
        config.append("nohints = true")
        config.append("")

    # nohttpinterface
    if not config_data['web_admin_ui']:
        config.append("nohttpinterface = true")
        config.append("")

    # noscripting
    if config_data['noscripting']:
        config.append("noscripting = true")
        config.append("")

    # notablescan
    if config_data['notablescan']:
        config.append("notablescan = true")
        config.append("")

    # noprealloc
    if config_data['noprealloc']:
        config.append("noprealloc = true")
        config.append("")

    # nssize
    if config_data['nssize'] != "default":
        config.append("nssize = %s" % config_data['nssize'])
        config.append("")

    # mms-token
    if config_data['mms-token'] != "disabled":
        config.append("mms-token = %s" % config_data['mms-token'])
        config.append("")

    # mms-name
    if config_data['mms-name'] != "disabled":
        config.append("mms-name = %s" % config_data['mms-name'])
        config.append("")

    # mms-interval
    if config_data['mms-interval'] != "disabled":
        config.append("mms-interval = %s" % config_data['mms-interval'])
        config.append("")

    # master/slave
    if config_data['master'] == "self":
        config.append("master = true")
        config.append("")
    else:
        config.append("slave = true")
        config.append("source = %s" % config_data['master'])
        config.append("")

    # arbiter
    if config_data['arbiter'] != "disabled" and \
    config_data['arbiter'] != "enabled":
        config.append("arbiter = %s" % config_data['arbiter'])
        config.append("")

    # autoresync
    if config_data['autoresync']:
        config.append("autoresync")
        config.append("")

    # oplogSize
    if config_data['oplogSize'] != "default":
        config.append("oplogSize = %s" % config_data['optlogSize'])
        config.append("")

    # opIdMem
    if config_data['opIdMem'] != "default":
        config.append("opIdMem = %s" % config_data['opIdMem'])
        config.append("")

    # extra config options
    if config_data['extra_config_options'] != "none":
        for config_option in config_data['extra_config_options'].split(','):
            config.append(config_option)

    return('\n'.join(config))


def mongo_client(host=None, command=None):
    if host is None or command is None:
        return(False)
    else:
        cmd_line = 'mongo'
        cmd_line += ' --host %s' % host
        cmd_line += ' --eval \'%s\'' % command
        juju_log("Executing: %s" % cmd_line)
        return(subprocess.call(cmd_line, shell=True) == 0)


def init_replset(master_node=None):
    if master_node is None:
        juju_log("init_replset: master_node must be defined.")
        retVal = False
    else:
        retVal = mongo_client(master_node, 'rs.initiate()')
    juju_log("init_replset returns: %s" % retVal)
    return(retVal)


def join_replset(master_node=None, host=None):
    juju_log("join_replset: master_node: %s, host: %s" %
    (master_node, host))
    if master_node is None or host is None:
        retVal = False
    else:
        retVal = mongo_client(master_node, "rs.add(\"%s\")" % host)
    juju_log("join_replset returns: %s" % retVal)
    return(retVal)


def enable_replset(replicaset_name=None):
    if replicaset_name is None:
        retVal = False
    try:
        mongodb_init_config = open(default_mongodb_init_config).read()
        if re.search(' --replSet %s ' % replicaset_name,
                     mongodb_init_config, re.MULTILINE) is None:
            mongodb_init_config = regex_sub([(' -- ',
                            ' -- --replSet %s ' % replicaset_name)],
                            mongodb_init_config)
        retVal = update_file(default_mongodb_init_config, mongodb_init_config)
    except Exception, e:
        juju_log(str(e))
        retVal = False
    finally:
        return(retVal)


def update_daemon_options(daemon_options=None):
    mongodb_init_config = open(default_mongodb_init_config).read()
    pat_replace = []
    if daemon_options is None or daemon_options == "none":
        pat_replace.append(
        (' --config /etc/mongodb.conf.*', ' --config /etc/mongodb.conf; fi'))
    else:
        pat_replace.append(
        (' --config /etc/mongodb.conf.*',
            ' --config /etc/mongodb.conf %s; fi' % daemon_options))
    regex_sub(pat_replace, mongodb_init_config)
    return(update_file(default_mongodb_init_config, mongodb_init_config))


def disable_replset(replicaset_name=None):
    if replicaset_name is None:
        retVal = False
    try:
        mongodb_init_config = open(default_mongodb_init_config).read()
        if re.search(' --replSet %s ' % replicaset_name,
                     mongodb_init_config, re.MULTILINE) is not None:
            mongodb_init_config = regex_sub([
                (' --replSet %s ' % replicaset_name, ' ')
                ],
                            mongodb_init_config)
        retVal = update_file(default_mongodb_init_config, mongodb_init_config)
    except Exception, e:
        juju_log(str(e))
        retVal = False
    finally:
        return(retVal)


def enable_web_admin_ui(port=None):
    if port is None:
        juju_log("enable_web_admin_ui: port not defined.")
        return(False)
    try:
        mongodb_init_config = open(default_mongodb_init_config).read()
        if re.search(' --rest ', mongodb_init_config, re.MULTILINE) is None:
            mongodb_init_config = regex_sub([(' -- ', ' -- --rest ')],
                                  mongodb_init_config)
        retVal = update_file(default_mongodb_init_config, mongodb_init_config)
    except Exception, e:
        juju_log(str(e))
        retVal = False
    finally:
        if retVal:
            open_port(port)
        return(retVal)


def disable_web_admin_ui(port=None):
    if port is None:
        juju_log("disable_web_admin_ui: port not defined.")
        return(False)
    try:
        mongodb_init_config = open(default_mongodb_init_config).read()
        if re.search(' --rest ',
            mongodb_init_config,
            re.MULTILINE) is not None:
            mongodb_init_config = regex_sub([(' --rest ', ' ')],
                                  mongodb_init_config)
        retVal = update_file(default_mongodb_init_config, mongodb_init_config)
    except Exception, e:
        juju_log(str(e))
        retVal = False
    finally:
        if retVal:
            close_port(port)
        return(retVal)


def enable_arbiter(master_node=None, host=None):
    juju_log("enable_arbiter: master_node: %s, host: %s" %
    (master_node, host))
    if master_node is None or host is None:
        retVal = False
    else:
        retVal = mongo_client(master_node, "rs.addArb(\"%s\")" % host)
    juju_log("enable_arbiter returns: %s" % retVal)
    return(retVal)


def configsvr_status(wait_for=default_wait_for, max_tries=default_max_tries):
    config_data = config()
    current_try = 0
    while (process_check_pidfile('/var/run/mongodb/configsvr.pid') !=
    (None, None)) and not port_check(
        unit_get('public-address'),
        config_data['config_server_port']) and current_try < max_tries:
        juju_log("configsvr_status: Waiting for Config Server to be ready ...")
        time.sleep(wait_for)
        current_try += 1
    retVal = (
        process_check_pidfile('/var/run/mongodb/configsvr.pid') != (None, None)
        ) == port_check(unit_get('public-address'),
        config_data['config_server_port']) is True
    if retVal:
        return(process_check_pidfile('/var/run/mongodb/configsvr.pid'))
    else:
        return((None, None))


def configsvr_ready(wait_for=default_wait_for, max_tries=default_max_tries):
    return(configsvr_status(wait_for, max_tries) != (None, None))


def disable_configsvr(port=None):
    if port is None:
        juju_log("disable_configsvr: port not defined.")
        return(False)
    try:
        config_server_port = config('config_server_port')
        pid = open('/var/run/mongodb/configsvr.pid').read()
        os.kill(int(pid), signal.SIGTERM)
        os.unlink('/var/run/mongodb/configsvr.pid')
        retVal = True
    except Exception, e:
        juju_log('no config server running ...')
        juju_log("Exception: %s" % str(e))
        retVal = False
    finally:
        juju_log("disable_configsvr returns %s" % retVal)
        close_port(config_server_port)
        return(retVal)


def enable_configsvr(config_data, wait_for=default_wait_for,
max_tries=default_max_tries):
    if config_data is None:
        juju_log("enable_configsvr: config_data not defined.")
        return(False)

    # Stop any running config servers
    disable_configsvr()

    # Make sure dbpath and logpath exist
    subprocess.call(
        [
            'mkdir',
            '-p',
            '%s' % config_data['config_server_dbpath']
        ]
        )
    subprocess.call(
        [
            'mkdir',
            '-p',
            '%s' % os.path.dirname(config_data['config_server_logpath'])
        ]
        )

    # Start the config server
    juju_log("enable_configsvr: Starting the config server")
    cmd_line = "mongod"
    cmd_line += " --configsvr"
    cmd_line += " --port %d" % config_data['config_server_port']
    cmd_line += " --dbpath %s" % config_data['config_server_dbpath']
    cmd_line += " --logpath %s" % config_data['config_server_logpath']
    cmd_line += " --pidfilepath /var/run/mongodb/configsvr.pid"
    cmd_line += " --fork"
    subprocess.call(cmd_line, shell=True)

    retVal = configsvr_ready(wait_for, max_tries)
    if retVal:
        open_port(config_data['config_server_port'])
        if config_data['web_admin_ui']:
            port = int(config_data['config_server_port']) + 1000
            open_port(port)
    juju_log("enable_configsvr returns: %s" % retVal)
    return(retVal)


def mongos_status(wait_for=default_wait_for, max_tries=default_max_tries):
    config_data = config()
    current_try = 0
    while (process_check_pidfile('/var/run/mongodb/mongos.pid') !=
    (None, None)) and not port_check(
        unit_get('public-address'),
        config_data['mongos_port']) and current_try < max_tries:
        juju_log("mongos_status: Waiting for Mongo shell to be ready ...")
        time.sleep(wait_for)
        current_try += 1
    retVal = \
        (process_check_pidfile('/var/run/mongodb/mongos.pid') !=
        (None, None)) == port_check(unit_get('public-address'),
            config_data['mongos_port']) is True
    if retVal:
        return(process_check_pidfile('/var/run/mongodb/mongos.pid'))
    else:
        return((None, None))


def mongos_ready(wait_for=default_wait_for, max_tries=default_max_tries):
    return(mongos_status(wait_for, max_tries) != (None, None))


def disable_mongos(port=None):
    if port is None:
        juju_log("disable_mongos: port not defined")
        return(False)
    try:
        pid = open('/var/run/mongodb/mongos.pid').read()
        os.kill(int(pid), signal.SIGTERM)
        os.unlink('/var/run/mongodb/mongos.pid')
        retVal = True
    except Exception, e:
        juju_log('no mongo router running ...')
        juju_log("Exception: %s" % str(e))
        retVal = False
    finally:
        juju_log("disable_mongos returns %s" % retVal)
        close_port(port)
        return(retVal)


def enable_mongos(config_data=None, config_servers=None,
    wait_for=default_wait_for, max_tries=default_max_tries):
    juju_log("enable_mongos")
    if config_data is None or config_servers is None:
        juju_log("enable_mongos: config_data and config_servers are mandatory")
        return(False)
    if not isinstance(config_servers, list):
        juju_log("enable_mongos: config_servers must be a list")
        return(False)
    if len(config_servers) < 3:
        juju_log("enable_mongos: Not enough config servers yet...")
        return(True)
    disable_mongos()
    # Make sure logpath exist
    subprocess.call(
        [
            'mkdir',
            '-p',
            '%s' % os.path.dirname(config_data['mongos_logpath'])
        ]
        )
    cmd_line = "mongos"
    cmd_line += " --logpath %s" % config_data['mongos_logpath']
    cmd_line += " --pidfilepath /var/run/mongodb/mongos.pid"
    cmd_line += " --port %d" % config_data['mongos_port']
    cmd_line += " --fork"
    if len(config_servers) > 0:
        if len(config_servers) >= 3:
            cmd_line += ' --configdb %s' % ','.join(config_servers[0:3])
#        else:
#            cmd_line += ' --configdb %s' % config_servers[0]
    juju_log("enable_mongos: cmd_line: %s" % cmd_line)
    subprocess.call(cmd_line, shell=True)
    retVal = mongos_ready(wait_for, max_tries)
    if retVal:
        open_port(config_data['mongos_port'])
    juju_log("enable_mongos returns: %s" % retVal)
    return(retVal)


def load_config_servers(mongos_list=None):
    if os.path.exists(mongos_list):
        retVal = [line.strip() for line in open(mongos_list).readlines()]
    else:
        retVal = []
    return(retVal)


def restart_mongod(wait_for=default_wait_for, max_tries=default_max_tries):
    my_hostname = unit_get('public-address')
    my_port = config('port')
    current_try = 0

    service('stop', 'mongodb')
    if os.path.exists('/var/lib/mongodb/mongod.lock'):
        os.remove('/var/lib/mongodb/mongod.lock')

    if not service('start', 'mongodb'):
        return False

    while (service('status', 'mongodb') and
           not port_check(my_hostname, my_port) and
           current_try < max_tries):
        juju_log(
            "restart_mongod: Waiting for MongoDB to be ready ({}/{})".format(
            current_try, max_tries))
        time.sleep(wait_for)
        current_try += 1

    return(
        (service('status', 'mongodb') == port_check(my_hostname, my_port))
         is True)


def backup_cronjob(disable=False):
    """Generate the cronjob to backup with mongodbump."""
    juju_log('Setting up cronjob')
    config_data = config()
    backupdir = config_data['backup_directory']
    bind_ip = config_data['bind_ip']
    cron_file = '/etc/cron.d/mongodb'
    cron_runtime = '@daily'

    # Disable or not remove it and regenerate it with new config data.
    if exists(cron_file):
        remove(cron_file)

    if not disable:
        tpl_data = {
            'backup_copies': config_data['backup_copies_kept'],
            'backup_directory': backupdir,
            'unique_name': os.environ.get('JUJU_UNIT_NAME', bind_ip),
            'bind_ip': bind_ip,
            'port': config_data['port'],
        }

        script_filename = '/var/lib/mongodb/cronbackup.py'
        script_template = 'templates/backup.py.tpl'

        juju_log('Writing out cronbackup.py')
        with open(script_template) as handle:
            template = Template(handle.read())
            rendered = template.substitute(tpl_data)

            with open(script_filename, 'w') as output:
                output.writelines(rendered)
            chmod(script_filename, 0755)

        juju_log('Installing cron.d/mongodb')

        if exists(cron_file):
            remove(cron_file)

        with open(cron_file, 'w') as output:
            output.write("""
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

%s    ubuntu python %s

""" % (cron_runtime, script_filename))


###############################################################################
# Hook functions
###############################################################################
@hooks.hook('install')
def install_hook():
    juju_log("Installing mongodb")
    add_source(config('source'), config('key'))
    apt_update(fatal=True)
    apt_install(packages=['mongodb', 'python-yaml'], fatal=True)
    return True


@hooks.hook('config-changed')
def config_changed():
    juju_log("Entering config_changed")
    print "Entering config_changed"
    config_data = config()
    print "config_data: ", config_data
    mongodb_config = open(default_mongodb_config).read()

    # Trigger volume initialization logic for permanent storage
    volid = volume_get_volume_id()
    if not volid:
        ## Invalid configuration (whether ephemeral, or permanent)
        stop_hook()
        mounts = volume_get_all_mounted()
        if mounts:
            juju_log("current mounted volumes: {}".format(mounts))
        juju_log(
            "Disabled and stopped mongodb service, "
            "because of broken volume configuration - check "
            "'volume-ephemeral-storage' and 'volume-map'")
        sys.exit(1)
    if volume_is_permanent(volid):
        ## config_changed_volume_apply will stop the service if it founds
        ## it necessary, ie: new volume setup
        if config_changed_volume_apply():
            start_hook()
        else:
            stop_hook()
            mounts = volume_get_all_mounted()
            if mounts:
                juju_log("current mounted volumes: {}".format(mounts))
            juju_log(
                "Disabled and stopped mongodb service "
                "(config_changed_volume_apply failure)")
            sys.exit(1)

    # current ports
    current_mongodb_port = re.search('^#*port\s+=\s+(\w+)',
        mongodb_config,
        re.MULTILINE).group(1)
    current_web_admin_ui_port = int(current_mongodb_port) + 1000
    new_web_admin_ui_port = int(config_data['port']) + 1000

    print "current_mongodb_port: ", current_mongodb_port
    public_address = unit_get('public-address')
    print "public_address: ", public_address

    # Update mongodb configuration file
    mongodb_config = mongodb_conf(config_data)
    update_file(default_mongodb_config, mongodb_config)

    if config_data['backups_enabled']:
        backup_cronjob()
    else:
        backup_cronjob(disable=True)

    # web_admin_ui
    if config_data['web_admin_ui']:
        enable_web_admin_ui(new_web_admin_ui_port)
    else:
        disable_web_admin_ui(current_web_admin_ui_port)

    # replicaset_master
    if config_data['replicaset_master'] != "auto":
        enable_replset(config_data['replicaset'])
        join_replset(config_data['replicaset_master'])

    # extra demon options
    update_daemon_options(config_data['extra_daemon_options'])

    # write mongodb logrotate configuration file
    write_logrotate_config(config_data)

    # restart mongodb
    restart_mongod()

    # attach to replSet ( if needed )
    if config_data['replicaset_master'] != "auto":
        join_replset(config_data['replicaset_master'], public_address)

    # arbiter
    if config_data['replicaset_master'] != 'auto':
        if config_data['arbiter'] != "disabled" and\
        config_data['replicaset_master'] != "auto":
            if config_data['arbiter'] == 'enable':
                enable_arbiter(config_data['replicaset_master'],
                "%s:%s" % (public_address, config_data['port']))
            else:
                enable_arbiter(config_data['replicaset_master'],
                config_data['arbiter'])

    # expose necessary ports
    update_service_ports([current_mongodb_port], [config_data['port']])

    if config_data['web_admin_ui']:
        current_web_admin_ui_port = int(current_mongodb_port) + 1000
        new_web_admin_ui_port = int(config_data['port']) + 1000
        close_port(current_web_admin_ui_port)
        open_port(new_web_admin_ui_port)

    # update config-server information and port
    try:
        (configsvr_pid, configsvr_cmd_line) = configsvr_status()
    except Exception, e:
        configsvr_pid = None
        configsvr_cmd_line = None
        juju_log("config_changed: configsvr_status failed.")
        juju_log("config_changed: Exception: %s" % str(e))

    if configsvr_pid is not None:
        configsvr_port = re.search('--port (\w+)', configsvr_cmd_line).group(2)
        disable_configsvr(configsvr_port)
        enable_configsvr(config_data['config_server_port'])
    else:
        open_port(config_data['config_server_port'])

    # update mongos information and port
    try:
        (mongos_pid, mongos_cmd_line) = mongos_status()
    except Exception, e:
        mongos_pid = None
        mongos_cmd_line = None
        juju_log("config_changed: mongos_status failed.")
        juju_log("config_changed: Exceptions: %s" % str(e))

    if mongos_pid is not None:
        mongos_port = re.search('--port (\w+)', mongos_cmd_line).group(1)
        disable_mongos(mongos_port)
        enable_mongos(config_data['mongos_port'])
    else:
        open_port(config_data['mongos_port'])

    print "About to leave config_changed"
    return(True)


@hooks.hook('start')
def start_hook():
    juju_log("start_hook")
    retVal = restart_mongod()
    juju_log("start_hook returns: %s" % retVal)
    return(retVal)


@hooks.hook('stop')
def stop_hook():
    juju_log("stop_hook")
    try:
        retVal = service('stop', 'mongodb')
        os.remove('/var/lib/mongodb/mongod.lock')
        #FIXME Need to check if this is still needed
    except Exception, e:
        juju_log(str(e))
        retVal = False
    finally:
        juju_log("stop_hook returns: %s" % retVal)
        return(retVal)


@hooks.hook('database-relation-joined')
def database_relation_joined():
    juju_log("database_relation_joined")
    my_hostname = unit_get('public-address')
    my_port = config('port')
    my_replset = config('replicaset')
    juju_log("my_hostname: %s" % my_hostname)
    juju_log("my_port: %s" % my_port)
    juju_log("my_replset: %s" % my_replset)
    return(relation_set(
        {
            'hostnme': my_hostname,
            'port': my_port,
            'replset': my_replset,
            'type': 'database',
        }))


@hooks.hook('replicaset-relation-joined')
def replica_set_relation_joined():
    juju_log("replica_set_relation_joined")
    my_hostname = unit_get('public-address')
    my_port = config('port')
    my_replset = config('replicaset')
    my_install_order = os.environ['JUJU_UNIT_NAME'].split('/')[1]
    juju_log("my_hostname: %s" % my_hostname)
    juju_log("my_port: %s" % my_port)
    juju_log("my_replset: %s" % my_replset)
    juju_log("my_install_order: %s" % my_install_order)
    enabled = enable_replset(my_replset)
    restarted = restart_mongod()

    relation_set(None, {
        'hostname': my_hostname,
        'port': my_port,
        'replset': my_replset,
        'install-order': my_install_order,
        'type': 'replset',
        })

    if enabled and restarted:
        return True
    return False

@hooks.hook('replicaset-relation-changed')
def replica_set_relation_changed():
    juju_log("replica_set_relation_changed")
    my_hostname = unit_get('public-address')
    my_port = config('port')
    my_install_order = os.environ['JUJU_UNIT_NAME'].split('/')[1]
    my_replicaset_master = config('replicaset_master')

    # If we are joining an existing replicaset cluster, just join and leave.
    if my_replicaset_master != "auto":
        return(join_replset(my_replicaset_master, my_hostname))

    # Default to this node being the master
    master_hostname = my_hostname
    master_port = my_port
    master_install_order = my_install_order

    # Check the nodes in the relation to find the master
    for member in relations_of_type('replica-set'):
        juju_log("replica_set_relation_changed: member: %s" % member['__unit__'])
        hostname = relation_get('hostname', member['__unit__'])
        port = relation_get('port', member['__unit__'])
        install_order = relation_get('install-order', member['__unit__'])
        juju_log("replica_set_relation_changed: install_order: %s" % install_order)
        if install_order is None:
            juju_log("replica_set_relation_changed: install_order is None.  relation is not ready")
            break
        if int(install_order) < int(master_install_order):
            master_hostname = hostname
            master_port = port
            master_install_order = install_order

    # Initiate the replset
    init_replset("%s:%s" % (master_hostname, master_port))

    # Add the rest of the nodes to the replset
    for member in relations_of_type('replica-set'):
        hostname = relation_get('hostname', member['__unit__'])
        port = relation_get('port', member['__unit__'])
        if master_hostname != hostname:
            if hostname == my_hostname:
                subprocess.call(['mongo',
                    '--eval',
                    "rs.add(\"%s\")" % hostname])
            else:
                join_replset("%s:%s" % (master_hostname, master_port),
                    "%s:%s" % (hostname, port))

    # Add this node to the replset ( if needed )
    if master_hostname != my_hostname:
        join_replset("%s:%s" % (master_hostname, master_port),
            "%s:%s" % (my_hostname, my_port))

    # should this always return true?
    return(True)


@hooks.hook('configsvr-relation-joined')
def configsvr_relation_joined():
    juju_log("configsvr_relation_joined")
    my_hostname = unit_get('public-address')
    my_port = config('config_server_port')
    my_install_order = os.environ['JUJU_UNIT_NAME'].split('/')[1]
    return(relation_set(None,
                        {
                            'hostname': my_hostname,
                            'port': my_port,
                            'install-order': my_install_order,
                            'type': 'configsvr',
                        }))


@hooks.hook('configsvr-relation-changed')
def configsvr_relation_changed():
    juju_log("configsvr_relation_changed")
    config_data = config()
    my_port = config_data['config_server_port']
    disable_configsvr(my_port)
    


@hooks.hook('mongos-cfg-relation-joined')
@hooks.hook('mongos-relation-joined')
def mongos_relation_joined():
    juju_log("mongos_relation_joined")
    my_hostname = unit_get('public-address')
    my_port = config('mongos_port')
    my_install_order = os.environ['JUJU_UNIT_NAME'].split('/')[1]
    relation_set(None,
                        {
                            'hostname': my_hostname,
                            'port': my_port,
                            'install-order': my_install_order,
                            'type': 'mongos'
                        })
    


@hooks.hook('mongos-cfg-relation-changed')
@hooks.hook('mongos-relation-changed')
def mongos_relation_changed():
    juju_log("mongos_relation_changed")
    config_data = config()
    retVal = False
    for member in relations_of_type('mongos-cfg'):
        hostname = relation_get('hostname', member['__unit__'])
        port = relation_get('port', member['__unit__'])
        rel_type = relation_get('type', member['__unit__'])
        if hostname is None or port is None or rel_type is None:
            juju_log("mongos_relation_changed: relation data not ready.")
            break
        if rel_type == 'configsvr':
            config_servers = load_config_servers(default_mongos_list)
            print "Adding config server: %s:%s" % (hostname, port)
            juju_log("Adding config server: %s:%s" % (hostname, port))
            if hostname is not None and \
            port is not None and \
            hostname != '' and \
            port != '' and \
            "%s:%s" % (hostname, port) not in config_servers:
                config_servers.append("%s:%s" % (hostname, port))
            disable_mongos(config_data['mongos_port'])
            retVal = enable_mongos(config_data, config_servers)
            if retVal:
                update_file(default_mongos_list, '\n'.join(config_servers))
        elif rel_type == 'database':
            if mongos_ready():
                mongos_host = "%s:%s" % (
                    unit_get('public-address'),
                    config('mongos_port'))
                shard_command1 = "sh.addShard(\"%s:%s\")" % (hostname, port)
                mongo_client(mongos_host, shard_command1)
                replicaset = relation_get('replset', member)
                shard_command2 = "sh.addShard(\"%s/%s:%s\")" %  \
                (replicaset, hostname, port)
                mongo_client(mongos_host, shard_command2)

        else:
            juju_log("mongos_relation_change: undefined rel_type: %s" %
                     rel_type)
            return(False)
    juju_log("mongos_relation_changed returns: %s" % retVal)
    return(retVal)


@hooks.hook('mongos-relation-broken')
def mongos_relation_broken():
    config_servers = load_config_servers(default_mongos_list)
    for member in relations_of_type('mongos'):
        hostname = relation_get('hostname', member)
        port = relation_get('port', member)
        if '%s:%s' % (hostname, port) in config_servers:
            config_servers.remove('%s:%s' % (hostname, port))

    update_file(default_mongos_list, '\n'.join(config_servers))



def run(command, exit_on_error=True):
    '''Run a command and return the output.'''
    try:
        juju_log(command)
        return subprocess.check_output(
            command, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError, e:
        juju_log("status=%d, output=%s" % (e.returncode, e.output))
        if exit_on_error:
            sys.exit(e.returncode)
        else:
            raise


###############################################################################
# Volume managment
###############################################################################
#------------------------------
# Get volume-id from juju config "volume-map" dictionary as
#     volume-map[JUJU_UNIT_NAME]
# @return  volid
#
#------------------------------
def volume_get_volid_from_volume_map():
    config_data = config()
    volume_map = {}
    try:
        volume_map = yaml.load(config_data['volume-map'].strip())
        if volume_map:
            juju_unit_name = os.environ['JUJU_UNIT_NAME']
            volid = volume_map.get(juju_unit_name)
            juju_log("Juju unit name: %s Volid:%s" % (juju_unit_name, volid))
            return volid
    except ConstructorError as e:
        juju_log("invalid YAML in 'volume-map': {}".format(e))
    return None


# Is this volume_id permanent ?
# @returns  True if volid set and not --ephemeral, else:
#           False
def volume_is_permanent(volid):
    if volid and volid != "--ephemeral":
        return True
    return False


#------------------------------
# Returns a mount point from passed vol-id, e.g. /srv/juju/vol-000012345
#
# @param  volid          volume id (as e.g. EBS volid)
# @return mntpoint_path  eg /srv/juju/vol-000012345
#------------------------------
def volume_mount_point_from_volid(volid):
    if volid and volume_is_permanent(volid):
        return "/srv/juju/%s" % volid
    return None


# Do we have a valid storage state?
# @returns  volid
#           None    config state is invalid - we should not serve
def volume_get_volume_id():
    config_data = config()
    ephemeral_storage = config_data['volume-ephemeral-storage']
    volid = volume_get_volid_from_volume_map()
    juju_unit_name = os.environ['JUJU_UNIT_NAME']
    if ephemeral_storage in [True, 'yes', 'Yes', 'true', 'True']:
        if volid:
            juju_log(
                "volume-ephemeral-storage is True, but " +
                "volume-map[{!r}] -> {}".format(juju_unit_name, volid))
            return None
        else:
            return "--ephemeral"
    else:
        if not volid:
            juju_log(
                "volume-ephemeral-storage is False, but "
                "no volid found for volume-map[{!r}]".format(
                    juju_unit_name))
            return None
        juju_log("Volid:%s" % (volid))
    return volid


# Initialize and/or mount permanent storage, it straightly calls
# shell helper
def volume_init_and_mount(volid):
    juju_log("Initialize and mount volume")
    command = ("scripts/volume-common.sh call " +
               "volume_init_and_mount %s" % volid)
    run(command)
    return True


def volume_get_all_mounted():
    command = ("mount |egrep /srv/juju")
    status, output = commands.getstatusoutput(command)
    if status != 0:
        return None
    return output

#------------------------------------------------------------------------------
# Core logic for permanent storage changes:
# NOTE the only 2 "True" return points:
#   1) symlink already pointing to existing storage (no-op)
#   2) new storage properly initialized:
#     - volume: initialized if not already (fdisk, mkfs),
#       mounts it to e.g.:  /srv/juju/vol-000012345
#     - if fresh new storage dir: rsync existing data
#     - manipulate /var/lib/mongodb/VERSION/CLUSTER symlink
#------------------------------------------------------------------------------
def config_changed_volume_apply():
    config_data = config()
    data_directory_path = config_data["dbpath"]
    assert(data_directory_path)
    volid = volume_get_volume_id()
    if volid:
        if volume_is_permanent(volid):
            if not volume_init_and_mount(volid):
                juju_log(
                    "volume_init_and_mount failed, not applying changes")
                return False

        if not os.path.exists(data_directory_path):
            juju_log(
                "mongodb data dir {} not found, "
                "not applying changes.".format(data_directory_path))
            return False

        mount_point = volume_mount_point_from_volid(volid)
        new_mongo_dir = os.path.join(mount_point, "mongodb")
        if not mount_point:
            juju_log(
                "invalid mount point from volid = {}, "
                "not applying changes.".format(mount_point))
            return False

        if os.path.islink(data_directory_path):
            juju_log(
                "mongodb data dir '%s' already points "
                "to %s, skipping storage changes." % (data_directory_path, new_mongo_dir))
            juju_log(
                "existing-symlink: to fix/avoid UID changes from "
                "previous units, doing: "
                "chown -R mongodb:mongodb {}".format(new_mongo_dir))
            run("chown -R mongodb:mongodb %s" % new_mongo_dir)
            return True

        # Create a directory structure below "new" mount_point
        curr_dir_stat = os.stat(data_directory_path)
        if not os.path.isdir(new_mongo_dir):
            juju_log("mkdir %s" % new_mongo_dir)
            os.mkdir(new_mongo_dir)
            # copy permissions from current data_directory_path
            os.chown(new_mongo_dir, curr_dir_stat.st_uid, curr_dir_stat.st_gid)
            os.chmod(new_mongo_dir, curr_dir_stat.st_mode)
        # Carefully build this symlink, e.g.:
        # /var/lib/mongodb ->
        # /srv/juju/vol-000012345/mongodb
        # but keep previous "main/"  directory, by renaming it to
        # main-$TIMESTAMP
        if not stop_hook():
            juju_log("stop_hook() failed - can't migrate data.")
            return False
        if not os.path.exists(new_mongo_dir):
            juju_log("migrating mongo data {}/ -> {}/".format(
                data_directory_path, new_mongo_dir))
            # void copying PID file to perm storage (shouldn't be any...)
            command = "rsync -a {}/ {}/".format(
                data_directory_path, new_mongo_dir)
            juju_log("run: {}".format(command))
            run(command)
        try:
            os.rename(data_directory_path, "{}-{}".format(
                data_directory_path, int(time.time())))
            juju_log("NOTICE: symlinking {} -> {}".format(
                new_mongo_dir, data_directory_path))
            os.symlink(new_mongo_dir, data_directory_path)
            juju_log(
                "after-symlink: to fix/avoid UID changes from "
                "previous units, doing: "
                "chown -R mongodb:mongodb {}".format(new_mongo_dir))
            run("chown -R mongodb:mongodb {}".format(new_mongo_dir))
            return True
        except OSError:
            juju_log("failed to symlink {} -> {}".format(
                data_directory_path, mount_point))
            return False
    else:
        juju_log(
            "Invalid volume storage configuration, not applying changes")
    return False


#------------------------------------------------------------------------------
# Write mongodb-server logrotate configuration
#------------------------------------------------------------------------------
def write_logrotate_config(config_data,
                           conf_file = '/etc/logrotate.d/mongodb-server'):

    juju_log('Writing {}.'.format(conf_file))
    contents = dedent("""
        {logpath} {{
                {logrotate-frequency}
                rotate {logrotate-rotate}
                maxsize {logrotate-maxsize}
                copytruncate
                delaycompress
                compress
                noifempty
                missingok
        }}""")
    contents = contents.format(**config_data)
    try:
        with open(conf_file, 'w') as f:
            f.write(contents)
    except IOError:
        juju_log('Could not write {}.'.format(conf_file))
        return False
    return True


###############################################################################
# Main section
###############################################################################
if __name__ == "__main__":
    # execute a hook based on the name the program is called by
    hooks.execute(sys.argv)

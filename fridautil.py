# coding: utf-8
__doc__ = 'Helper methods to do frida Adnroid DBI'

import os
import time
import re
# https://pypi.org/project/frida/
import frida
import func_timeout
import common

class FridaServerFileNotFound(Exception):
    """Exception for can not find the frida server bin file
    """
    pass

class FridaServerNotStarted(Exception):
    """Exception for failed to start the frida server
    """
    pass

class FridaNoDeviceMatched(Exception):
    """Exception for not found matched device
    """
    pass


def start_frida_server(serialno=None, restart=False, forward_port=True, frida_path='/data/local/tmp/frida'):
    """Start the frida server backend
        
    serialno:
        the device serialno;
    restart:
        whether to restart the frida backend;
    forward_port:
        whether to forward the frida port;
    frida_path:
        the path of the frida server bin file;
    """
    adb_cmd_prefix = 'adb '
    if serialno:
        adb_cmd_prefix = 'adb -s "{}" '.format(serialno)    
    while True:
        if serialno and ':' in serialno:
            common.command('adb connect ' + serialno)
        # check whether the device is offline
        cmd_ret = common.command(adb_cmd_prefix + ' shell date')
        if 'device offline' in cmd_ret:
            common.logger.error(u'Device "{}" is offline, will check again later.'.format(serialno))
            # disconnect the device
            common.command('adb disconnect ' + serialno)
            time.sleep(1)
        else:
            break
    # is the frida server bin file is ready?
    cmd_ret = common.command(adb_cmd_prefix + ' shell "ls {}"'.format(frida_path))
    if not cmd_ret or 'No such file' in cmd_ret:
        raise FridaServerFileNotFound('Can not find the frida server bin file "{}".'.format(frida_path))
    
    if restart:
        # Kill the existed frida server process
        allprocesses_lines = common.command(adb_cmd_prefix + ' shell ps')
        for line in allprocesses_lines.splitlines():
            if os.path.basename(frida_path) in line:
                frida_pid = line.split()[1].strip()
                cmd = adb_cmd_prefix + ' shell "su -c \'kill -9 {}\'"'.format(frida_pid)
                common.command(cmd)
                time.sleep(1)        
        
    # whether the frida server is running
    cmd_ret = common.command(adb_cmd_prefix + ' shell ps')
    if os.path.basename(frida_path) not in cmd_ret:
        common.logger.info(u'The frida server is not running, will start it...')
        common.command(adb_cmd_prefix + ' shell "su -c \'chmod 777 {}\'"'.format(frida_path))
        common.command(adb_cmd_prefix + ' shell "su -c \'nohup {} -l 0.0.0.0 > /sdcard/frida-server.log 2>&1 &\'"'.format(frida_path))
        if os.path.basename(frida_path) in common.command(adb_cmd_prefix + ' shell ps'):
            common.logger.info(u'Frida server is runing.')
        else:
            common.logger.error(u'Frida server is not started.')
            raise FridaServerNotStarted('Failed to start the frida server "{}"'.format(frida_path))
    else:
        common.logger.info(u'Frida server is runing.')

    if forward_port:
        # do port forwarding for frida server
        common.command(adb_cmd_prefix + ' forward tcp:27042 tcp:27042')
        common.command(adb_cmd_prefix + ' forward tcp:27043 tcp:27043')
    return True



def inject_script(package, scriptcode, serialno=None, on_message_fun=None, restart=False, remote_connect=False):
    """Inject instrumentation code into destination app process
    
    package:
        app package name;
    scriptcode:
        the javascript code to be injected;
    serialno:
        the device serialno;        
    on_message_fun:
        callback function to process the script messages;
    restart:
        if true will spawn the app;
    remote_connect:
        if true will connect the remote frida server with add_remote_device() method   
    """
    adb_cmd_prefix = 'adb '
    if serialno:
        adb_cmd_prefix = 'adb -s "{}" '.format(serialno)
    device = None
    if serialno:
        if ':' in serialno:
            if remote_connect:
                # remote connect the frida server
                frida_server_ip_port = re.sub(r'\:\d+', '', serialno).strip() + ':27042'
                common.logger.info(u'Remote connect to the frida server "{}"'.format(frida_server_ip_port))            
                device = frida.get_device_manager().add_remote_device(frida_server_ip_port)
            else:
                device = None
                for _device in frida.enumerate_devices():
                    if _device.id == serialno:
                        device = _device
                        break
                if not device:
                    device = frida.get_remote_device()
        else:
            device = frida.get_usb_device()
    else:
        device = frida.get_remote_device()    

    if not device:
        raise FridaNoDeviceMatched('Not found matched device(serialno={}).'.format(serialno))
    else:
        if restart:
            # Spawn model
            pid = device.spawn([package])
            device.resume(pid)
            time.sleep(3)
            session = device.attach(pid)
        else:
            # attach model
            app_started = False
            for process in device.enumerate_processes():
                if process.name == package:
                    app_started = True
                    break
            if not app_started:
                common.logger.info(u'App {} not started, will start it.'.format(package))
                common.command(adb_cmd_prefix + ' shell "su -c \'monkey -p {} 1\'"'.format(package))
                time.sleep(3)
            session = device.attach(package)
    script = session.create_script(scriptcode)
    if on_message_fun:
        script.on('message', on_message_fun)
    script.load()
    return script




class FridaClient:
    
    def __init__(self, package, scriptcode, serialno=None, on_message_fun=None, restart_frida=False, restart_app=False, forward_port=True, remote_connect=False, inject_oninit=True, frida_path='/data/local/tmp/frida'):
        """
        package:
            app package name;
        scriptcode:
            the javascript code to be injected;
        serialno:
            the device serialno;        
        on_message_fun:
            callback function to process the script messages; 
        restart_frida:
            whether to restart the frida backend;
        restart_app:
            if true will spawn the app;
        forward_port:
            whether to forward the frida port;
        remote_connect：
            if true will connect the remote frida server with add_remote_device() method
        inject_oninit：
            if true will do inject() in this init method
        frida_path:
            the path of the frida server bin file;            
        """
        self.serialno = serialno
        self.package = package
        self.scriptcode = scriptcode
        self.on_message_fun = on_message_fun
        self.restart_frida = restart_frida
        self.restart_app = restart_app
        self.forward_port = forward_port
        self.remote_connect = remote_connect
        self.frida_path = frida_path
        self.script = None
        if inject_oninit:
            self.inject()
        
        
    def inject(self):
        """Do frida inject and return script object
        """
        start_frida_server(serialno=self.serialno, restart=self.restart_frida, forward_port=self.forward_port, frida_path=self.frida_path)
        self.script = inject_script(package=self.package, scriptcode=self.scriptcode, serialno=self.serialno, on_message_fun=self.on_message_fun, restart=self.restart_app, remote_connect=self.remote_connect)
        
    def callrpc(self, method, args=None, timeout=5, num_retries=3):
        """Call Frida RPC method and return result
       
        method:
            the frida rpc function name
        args:
            a list, the args data of the  rpc function
        timeout:
            max time(secods) to wait before raise TimeoutError exception
        num_retries:
            max retries number   
        """
        @func_timeout.func_set_timeout(timeout)
        def safecallrpc(fc, method, args):
            result = None
            num_failed = 0
            while True:
                try:
                    if not fc.script:
                        fc.inject()
                        num_failed = 0
                    try:
                        rpcfun = getattr(fc.script.exports, method)
                    except AttributeError:
                        common.logger.error('No such frida exports rpc method "{}".'.format(method))
                        return
                    else:
                        result = rpcfun(*args) if args else rpcfun()
                except Exception, e:
                    error = common.to_unicode(str(e))
                    common.logger.error(u'Failed to call rcp "{}": {}.'.format(method, error))
                    if u'script is destroyed' in error:
                        common.logger.error('"script is destroyed", will re-do code injection.')
                        fc.inject()
                        num_failed = 0
                    else:
                        num_failed += 1
                    time.sleep(1)
                else:
                    num_failed = 0
                    break
                if num_failed >= 3:
                    common.logger.error('Too many times fails for rpc call "{}", will re-do code injection.'.format(method))
                    fc.inject()
                    num_failed = 0
            return result
        
        retries = 0
        while retries < num_retries:
            try:
                result = safecallrpc(self, method, args)
            except func_timeout.exceptions.FunctionTimedOut:
                common.logger.error('Timedout to call rcp "{}", will re-do code injection.'.format(method))
                self.inject()
                retries += 1
            else:
                return result
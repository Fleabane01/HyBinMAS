import os
import subprocess

import frida
from frida.core import Script


class FridaUtils:
    def __init__(self, target_module: str, port: int = 1234, target_process=None):
        try:
            self.device: frida.core.Device = frida.get_device_manager().add_remote_device(f"127.0.0.1:{port}")
            pid = self.device.get_frontmost_application().pid
            print(pid)
            self.session: frida.core.Session = self.device.attach(pid)
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "_agent.js"), "r", encoding='utf-8') as f:
                script_source = f.read()
            self.script: Script = self.session.create_script(script_source)
            self.script.on('message', self._dispatch_message)
            self.script.load()
            self.exports = self.script.exports_sync

            self.module = target_module
        except Exception as e:
            self.cleanup()
            raise Exception(str(e))

    def cleanup(self):
        try:
            subprocess.run(
                ["adb", "shell", "pkill", "-9", "-f", "fs17.2.0"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            if hasattr(self, 'session'):
                self.session.detach()
                print("[+] disconnected")

            print("[+] frida-server killed")
        except Exception as e:
            print("[!] error:", e)


    def add_on_message(self, handler):
        if callable(handler):
            self._custom_message_handler = handler
        else:
            raise TypeError("handler not callable")

    def _dispatch_message(self, message, data):
        if self._custom_message_handler:
            self._custom_message_handler(message, data)
        else:
            print("[!] without handler:", message)

    def hook_specified_function_with_stalker(
            self,
            idx: int,
            begin_offset_str: str,
            end_offset_str: str,
            write_args_body: str,
            read_args_body: str,
            read_ret_body: str
    ):
        begin_offset = int(begin_offset_str, 16)
        end_offset = int(end_offset_str, 16)
        self.exports.hook_specified_function_with_stalker(self.module, idx, begin_offset, end_offset, write_args_body, read_args_body, read_ret_body)
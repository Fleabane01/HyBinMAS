import argparse
import json
import logging
import os
import subprocess
import threading
import time
import random
from typing import Dict

from utils.cache import PersistentCache
from frida_scripts.frida_utils import FridaUtils
from utils.common_utils import get_logger

PROJECTS_FOLDER = "" # TODO replace with actual folder

def check_foreground_activity(target_str: str) -> bool:
    result = subprocess.run(
        ["adb", "shell", "dumpsys", "window", "windows"],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        for part in parts:
            if target_str in part:
                return True
    return False

def start_frida(package_name: str, so_name: str) -> FridaUtils:
    def frida_server_thread():
        print("start frida server...")
        start_frida_server_cmd = [
            "adb", "shell",
            "/data/local/tmp/fs17.2.0", "-l", "127.0.0.1:1234"
        ]
        subprocess.run(start_frida_server_cmd)

    t = threading.Thread(target=frida_server_thread, daemon=True)
    t.start()

    time.sleep(3)

    adb_forward_cmd = [
        "adb", "forward",
        "tcp:1234", "tcp:1234"
    ]
    print("set adb forward...")
    subprocess.run(adb_forward_cmd)

    frida_utils = FridaUtils(so_name)

    return frida_utils


def run_monkey(
        seed: int,
        metadata: Dict[str, str]
):
    package_name = metadata['packageName']
    main_activity = metadata['mainActivity']

    total_event_count = 1000
    batch_size = 50
    check_interval = 1
    throttle = 400
    pct_touch = 60
    pct_motion = 23
    pct_trackball = 0
    pct_syskeys = 1
    pct_nav = 5
    pct_majornav = 10
    pct_flip = 0
    pct_anyevent = 0
    pct_pinchzoom = 1

    try:
        subprocess.run(["adb", "shell", "rm", "-f", "/data/tombstones/tombstone_*"])

        target_str = f"{package_name}/{main_activity}"

        offset_size = 1000000
        for batch_index in range(total_event_count // batch_size):
            batch_seed = seed + offset_size * batch_index

            cmd = [
                "adb", "shell", "monkey",
                "-p", package_name,
                "-s", str(batch_seed),
                "--throttle", str(throttle),
                "--pct-touch", str(pct_touch),
                "--pct-motion", str(pct_motion),
                "--pct-trackball", str(pct_trackball),
                "--pct-syskeys", str(pct_syskeys),
                "--pct-nav", str(pct_nav),
                "--pct-majornav", str(pct_majornav),
                "--pct-flip", str(pct_flip),
                "--pct-anyevent", str(pct_anyevent),
                "--pct-pinchzoom", str(pct_pinchzoom),
                "--ignore-crashes",
                "--ignore-timeouts",
                "--ignore-security-exceptions",
                "--monitor-native-crashes",
                str(batch_size)
            ]

            print(f"\n=== exec batch {batch_index+1} / {total_event_count // batch_size}，seed={batch_seed} ===")

            subprocess.run(cmd)

            if not check_foreground_activity(target_str):
                print("restart")
                subprocess.run(["adb", "shell", "am", "start", f"{package_name}/{main_activity}"])
                time.sleep(1)

            time.sleep(check_interval)
    finally:
        print("\n monkey test over")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--p', help='project_name')
    parser.add_argument('--f', help='so_name')
    parser.add_argument('--method', default="monkey", help="exec method")
    parser.add_argument('--seed', type=int, default=1234)
    parser.add_argument('--use_potential', action='store_true')
    args = parser.parse_args()
    project_name = args.p
    so_name = args.f
    method = args.method
    seed = args.seed
    use_potential = args.use_potential

    logger = get_logger(f"exec_{project_name}_{so_name}", level=logging.INFO)

    exec_target_path = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "exec", f"target_{so_name}.json")
    with open(exec_target_path, 'r', encoding='utf-8') as f:
        exec_target = json.load(f)
    exec_path = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "exec", f"{so_name}.json")
    cache = PersistentCache(f"{project_name}", table_name=so_name[:-3].replace(".", "_"), folder="exec", use_history=True)
    cache.import_from_json(exec_path)

    with open(os.path.join(PROJECTS_FOLDER, project_name, "metadata.json"), "r", encoding='utf-8') as f:
        metadata = json.load(f)

    logger.info(f"[EXEC] BEGIN {project_name} -> {so_name}, number = {len(exec_target)}")

    batch_size = 5
    random.seed(seed)
    keys = list(exec_target.keys())
    if use_potential:
        with open(os.path.join(PROJECTS_FOLDER, project_name, "potential_func", f"{so_name}.json")) as f:
            potential_func = set(json.load(f))
            keys = [key for key in keys if key in potential_func]
        batch_size = 2

    random.shuffle(keys)
    seeds = [1231, 1232, 1234, 1235, 1241, 1240, 1239, 1238, 1236]
    for seed in seeds:
        for i in range(0, len(keys), batch_size):
            batch_keys = keys[i:i + batch_size]
            logger.info(f"[EXEC] BATCH = {{{batch_keys}}}")
            frida_utils = None
            try:
                package_name = metadata['packageName']
                main_activity = metadata['mainActivity']

                subprocess.run(["adb", "shell", "am", "force-stop", package_name])
                time.sleep(1)

                subprocess.run(["adb", "shell", "am", "start", f"{package_name}/{main_activity}"])

                def on_message(message, data):
                    if message['type'] == 'error':
                        error_msg = {message.get('stack') or message.get('message', 'Unknown error')}
                        fmt_error = ""
                        if 'onEnter (agent/stalker_util.ts:232)' in error_msg:
                            fmt_error = f"[!] writeArgs error: {error_msg}"
                        elif 'onLeave (agent/stalker_util.ts:329)' in error_msg:
                            fmt_error = f"[!] readArgs error: {error_msg}"
                        elif 'onLeave (agent/stalker_util.ts:347)' in error_msg:
                            fmt_error = f"[!] readRet error: {error_msg}"
                        else:
                            fmt_error = error_msg
                        logger.error(fmt_error)

                    if message['type'] == 'send':
                        payload = message['payload']
                        message_type = payload['type']
                        _offset = payload['offset']
                        _offset = f"{_offset:08x}" # 修正为十六进制的形式
                        _idx = payload['idx']
                        content = payload['content']
                        logger.info(f"[EXEC] receive message from frida, msg = {message['payload']}")
                        if message_type == 'func-create-error':
                            logger.error(f"offset = {_offset}, idx = {_idx}, function create error: {content}")
                            exec_target[_offset][0]['exec']['success'] = False
                            exec_target[_offset][0]['exec']['error_info'] = content
                        elif message_type == 'writeArgs-error':
                            logger.error(f"offset = {_offset}, idx = {_idx}, writeArgs exec error: {content}")
                            exec_target[_offset][0]['exec']['success'] = False
                            old = exec_target[_offset][0]['exec'].get('error_info', "")
                            exec_target[_offset][0]['exec']['error_info'] = old + f"writeArgs exec error: {content}" + '\n'
                        elif message_type == 'readArgs-error':
                            logger.error(f"offset = {_offset}, idx = {_idx}, readArgs exec error: {content}")
                            exec_target[_offset][0]['exec']['success'] = False
                            old = exec_target[_offset][0]['exec'].get('error_info', "")
                            exec_target[_offset][0]['exec']['error_info'] = old + f"readArgs exec error: {content}" + '\n'
                        elif message_type == 'readRet-error':
                            logger.error(f"offset = {_offset}, idx = {_idx}, readRet exec error: {content}")
                            exec_target[_offset][0]['exec']['success'] = False
                            old = exec_target[_offset][0]['exec'].get('error_info', "")
                            exec_target[_offset][0]['exec']['error_info'] = old + f"readRet exec error: {content}" + '\n'
                        elif message_type == 'args':
                            logger.info(f"offset = {_offset}, idx = {_idx}, readArgs:", content)
                            exec_target[_offset][0]['exec']['success'] = True # 由于三者同时发出，所以只需要记录一个即可
                            exec_target[_offset][0]['exec'].setdefault('execution_info', {})['actual_args'] = content
                        elif message_type == 'ret':
                            logger.info(f"offset = {_offset}, idx = {_idx}, readRet:", content)
                            exec_target[_offset][0]['exec'].setdefault('execution_info', {})['actual_ret'] = content
                        elif message_type == 'trace':
                            logger.info(f"offset = {_offset}, idx = {_idx}, trace:", content)
                            exec_target[_offset][0]['exec'].setdefault('execution_info', {})['trace'] = content

                logger.info(f"[EXEC] start frida")
                time.sleep(12)
                frida_utils = start_frida(project_name, so_name)
                time.sleep(2)
                frida_utils.add_on_message(on_message)
                # hook a batch
                for key in batch_keys:
                    if not exec_target[key]:
                        logger.warning(f"[EXEC] empty, skip hooking, offset = {key}")
                        continue
                    item = exec_target[key][0]
                    idx = item['idx']
                    begin_offset_str = item['begin_offset']
                    end_offset_str = item['end_offset']
                    write_args_body = item['impl']['writeArgs']
                    read_args_body = item['impl']['readArgs']
                    read_ret_body = item['impl']['readRet']
                    logger.info(f"[EXEC] begin hook begin_offset = {begin_offset_str}, end_offset = {end_offset_str}, write_args = {write_args_body}, read_args = {read_args_body}, read_ret = {read_ret_body}")
                    frida_utils.hook_specified_function_with_stalker(idx, begin_offset_str, end_offset_str, write_args_body, read_args_body, read_ret_body)
                    time.sleep(0.5)


                time.sleep(5)
                if method == 'monkey':
                    logger.info(f"[EXEC] run monkey on seed = {seed}")
                    run_monkey(seed=seed, metadata=metadata)
                time.sleep(5)

                frida_utils.cleanup()

                logger.info("[EXEC] DONE")

                for key in batch_keys:
                    if key not in exec_target or not exec_target[key]:
                        logger.warning(f"[EXEC] empty, skip saving, offset = {key}") # 直接pass
                        continue
                    item = exec_target[key][0]
                    idx = item['idx']
                    if 'success' in item['exec']:
                        logger.info(f"[EXEC] SUCCESS, offset = {key}, exec = {item['exec']}")
                        if cache.has_key(key):
                            exec_info = cache.get(key)
                            exec_info[str(idx)]['exec'] = item['exec'] # 注意是字符串
                            cache.set(key, exec_info)
                        exec_target[key].pop(0)
                        logger.info("[EXEC] update exec_info and exec_target")
                        if len(exec_target[key]) == 0:
                            logger.info(f"[EXEC] All test cases complete, offset = {key}, idx = {idx}")
                            del exec_target[key] # 删除该key


                with open(exec_target_path, 'w', encoding='utf-8') as f:
                    json.dump(exec_target, f)
                cache.export_to_json(exec_path)

                logger.info("[EXEC] SAVED")

                time.sleep(2)
            except Exception as e:
                logger.error(f"[EXEC] ERROR, msg = {str(e)}")
            finally:
                if frida_utils:
                    frida_utils.cleanup()


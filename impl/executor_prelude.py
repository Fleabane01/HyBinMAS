import argparse
import json
import logging
import os
from typing import Dict, List, Any

from utils.cache import PersistentCache
from utils.common_utils import get_logger

PROJECTS_FOLDER = "" # TODO replace with actual folder


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--p', help='project_name')
    parser.add_argument('--f', help='so_name')
    # parser.add_argument("--use_history", action='store_true', help="use history?")
    # parser.add_argument('--load_json', action='store_true', help="cache json from path?")
    # parser.add_argument("--use_call_relation", action='store_true', help='use call relation?')
    # parser.add_argument("--use_dynamic_info", action='store_true', help='use dynamic info?')
    args = parser.parse_args()
    project_name = args.p
    so_name = args.f

    logger = get_logger(f"exec_{project_name}_{so_name}", level=logging.INFO)

    tg_path = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "tg", f"{so_name}.json")
    with open(tg_path, 'r', encoding='utf-8') as f:
        tg = json.load(f)

    with open(os.path.join(PROJECTS_FOLDER, project_name, "aligned_call", "all_funcs", f"{so_name}.json"), 'r', encoding='utf-8') as f:
        all_funcs = json.load(f)

    exec: Dict[str, Dict[int, Any]] = {}
    exec_target: Dict[str, List[Dict[str, Any]]] = {}
    for offset, info_list in tg.items():
        info = info_list[-1]
        if "tg_materializer" not in info:
            logger.error(f"[EXEC] ERROR: NOT IMPL, offset = {offset}")
            continue
        impl_list = info['tg_materializer']
        for i, impl in enumerate(impl_list):
            if impl_list[i]['impl_version'] > impl_list[i]['exec_version'] and not impl_list[i].get("exec", {"success": False})['success']:
                exec_target.setdefault(offset, []).append({
                    "idx": i,
                    "impl": impl['impl'],
                    "begin_offset": all_funcs[offset]['function_offset']['start'],
                    "end_offset": all_funcs[offset]['function_offset']['end'],
                    "exec": {}
                })
                # logger.info(f"[EXEC] PASS, offset = {offset}, impl = {impl}, ids = {i}")
                exec.setdefault(offset, {})[i] = {
                    "impl": impl['impl'],
                    "begin_offset": all_funcs[offset]['function_offset']['start'],
                    "end_offset": all_funcs[offset]['function_offset']['end'],
                    "exec": {}
                }


    exec_target_path = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "exec", f"target_{so_name}.json")
    os.makedirs(os.path.dirname(exec_target_path), exist_ok=True)
    with open(exec_target_path, 'w', encoding='utf-8') as f:
        json.dump(exec_target, f)
    exec_path = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "exec", f"{so_name}.json")
    with open(exec_path, 'w', encoding='utf-8') as f:
        json.dump(exec, f)
    cache = PersistentCache(f"{project_name}", table_name=so_name[:-3], folder="exec", use_history=True)
    if os.path.exists(exec_path):
        cache.import_from_json(exec_path)


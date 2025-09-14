import argparse
import json
import logging
import os

from utils.common_utils import get_logger

PROJECTS_FOLDER = "" # TODO replace with actual folder


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--p', help='project_name')
    parser.add_argument('--f', help='so_name')
    args = parser.parse_args()
    project_name = args.p
    so_name = args.f

    logger = get_logger(f"exec_{project_name}_{so_name}", level=logging.INFO)

    dy_path = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "tg", f"{so_name}.json")
    with open(dy_path, 'r', encoding='utf-8') as f:
        dy = json.load(f)

    exec_path = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "exec", f"{so_name}.json")
    with open(exec_path, 'r', encoding='utf-8') as f:
        exec_info = json.load(f)

    for offset, ex_info in exec_info.items():
        idx_list = sorted(ex_info.keys())
        for idx in idx_list:
            if 'exec' not in ex_info[idx]:
                continue
            ex = ex_info[idx]['exec']
            info = dy[offset][-1]
            if 'tg_materializer' in info:
                info[idx]['exec'] = ex

    with open(dy_path, 'w', encoding='utf-8') as f:
        json.dump(dy, f)





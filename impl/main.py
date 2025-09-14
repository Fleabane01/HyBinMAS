import argparse
import logging
import os.path

from semantic_restorer_dynamic import sr_process_dynamic
# from executor import executor_init
from semantic_restorer_static import sr_process_static
from utils.common_utils import get_logger


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--p', required=True, help='project_name')
    parser.add_argument('--f', required=True, help='so_name')
    parser.add_argument("--use_history", action='store_true', help="use history?")
    parser.add_argument('--load_json', action='store_true', help="cache json from path?")
    parser.add_argument("--use_call_relation", action='store_true', help='use call relation?')
    parser.add_argument("--use_dynamic_info", action='store_true', help='use dynamic info?')
    parser.add_argument("--arch", default="arm64-v8a", help='arch info')
    parser.add_argument("--iter", type=int, default=1, help='arch info')
    args = parser.parse_args()
    project_name = args.p
    so_name = args.f
    use_history = args.use_history
    is_load_json = args.load_json
    use_call_relation = args.use_call_relation
    use_dynamic_info = args.use_dynamic_info
    arch = args.arch
    iter = args.iter

    if use_dynamic_info:
        logger = get_logger(f"dynamic_{project_name}{so_name}", level=logging.INFO)
        sr_process_dynamic(project_name, so_name, logger, use_history, is_load_json, use_call_relation=True, arch_info=arch, iter=iter)
    else:
        logger = get_logger(f"static_{project_name}{so_name}", level=logging.INFO)
        sr_process_static(project_name, so_name, logger, use_history, is_load_json, use_call_relation=use_call_relation, arch_info=arch)
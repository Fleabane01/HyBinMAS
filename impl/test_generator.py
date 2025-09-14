import argparse
import json
import logging
import os
import re
from typing import Dict, List

import requests
from openai import OpenAI

from utils.timer import Timer
from utils.common_utils import get_logger, makedirs_if_necessary

PROJECTS_FOLDER = "" # TODO replace with actual folder

def tg_query_LLM_for_orchestrator(sr: Dict[str, str], pseudo: str, program_slice: Dict[str, str], logger: logging.Logger, architecture = "arm64-v8a") -> (int, List[Dict[str, str]]):
    """
    :return: List[{
        "explanation": xxx,
        "input_args": xxx,
        "expected_args": xxx,
        "expected_ret": xxx
    }]
    """

    url = "your url"  # TODO replace with actual url

    api_key = "your api key"  # TODO replace with actual API key

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    client = OpenAI(api_key=api_key, base_url=url)

    program_slice_str = ""
    for k, v in program_slice.items():
        program_slice_str += f"{k}:\n{v}\n"

    content = f"""
Architecture: 
{architecture}
Pseudo: 
{pseudo}
Func name: 
{sr['func_name']}
Summarization:
{sr['summarization']}
Program Slice:
{program_slice_str.rstrip('\n')}

Requirements:
1. The output test sample consists of four parts: explanation is used to explain the test sample, including the content or purpose of which aspect is to be tested; "input_args" is used to indicate what kind of modification operation is performed on the input parameters; "expected_args" indicates what the expected value of the parameter is after the function finishes running. expected_ret indicates what the actual value of the parameter is after the function finishes running
2. You should return a JSON format representing a list, each of which is a valid JSON Object, representing a test sample
"""

    try:
        response = client.chat.completions.create(
            model="deepseek-r1",
            messages=[
                {"role": "system",
                 "content": "You are an expert in the design of test samples. You need to verify the functionality of a function based on the appropriate test samples involved in its comment information"},
                {"role": "user", "content": content},
            ],
            max_tokens=1024,
            stream=False
        )

        content = response.choices[0].message.content

        res = json.loads(re.sub(r"^```json\s*|\s*```$", "", content, flags=re.MULTILINE))

        return 0, res
    except Exception as e:
        return 0, []

def format_args_info(args_info: List):
    if len(args_info) == 0:
        return "no args"
    else:
        res = []
        for arg in args_info:
            # res.append(f"{arg['name']}'s type is {arg['type']}({arg['width']}B), store at {arg['storage']}")
            res.append(f"""{arg['name']}'s type is "{arg['type']}" ({arg['width']} byte), store at {arg['storage']}""")
        return "\n".join(res)

def format_ret_info(ret_info: Dict):
    if ret_info['type'] == 'void':
        return 'return type is void'
    else:
        if ret_info['width'] > 0 and ret_info['storage']:
            # return f"return type is {ret_info['type']}({ret_info['width']}B), store at {ret_info['storage']}"
            return f"""return type is "{ret_info['type']}" ({ret_info['width']} byte), store at {ret_info['storage']}"""
        else:
            return ret_info['type']

def tg_query_LLM_for_materializer(pseudo: str, test_case: Dict, args_info: List, ret_info: Dict, error_info: Dict, logger: logging.Logger) -> (int, Dict):
    """
    :return: List[{
        "explanation": xxx,
        "input_args": xxx,
        "expected_args": xxx,
        "expected_ret": xxx
    }]
    """

    url = "your url" # TODO replace with actual url

    api_key = "your api key" # TODO replace with actual API key

    client = OpenAI(api_key=api_key, base_url=url)

    test_case_str = json.dumps(test_case)

    background_knowledge = ""

    content = f"""
{background_knowledge}
1. Decompiled pseudo-C code of the target function
{pseudo}
2. Test case specification from the Orchestrator, including: explanation, input_args, expected_args, expected_ret;
{test_case_str}
3.args_info, ret_info
{format_args_info(args_info)}
{format_ret_info(ret_info)}

Requirements:
1. Write only the specified fields in `input_args` to the correct registers or memory locations.
2. Read the parameter values specified in `expected_args` from registers or memory.
3. Read the return value specified in `expected_ret` from the appropriate register.
4. For structures, compute byte offsets using element size (e.g., `param_1[0x17]` → `0x17 * element_size`). Output must be  with exactly three keys: `"writeArgs"`, `"readArgs"`, `"readRet"`

An output example as follows:
{{
    "writeArgs": "ctx.x0 = ptr(0)",
    "readArgs": "let args0 = ctx.x0.toInt32();\nreturn `parma_0 = ${{args0}}`",
    "readRet": "let retVal = ctx.x0.toInt32();\nreturn `return value = ${{retVal}}`",
}}
    """

    try:
        response = client.chat.completions.create(
            model="deepseek-r1",
            messages=[
                {"role": "system",
                 "content": "You are a test case implementer, responsible for transforming natural language descriptions of test cases into executable code.\nGiven the semantic description of a binary function, its decompiled pseudo-C code, and a set of test cases designed by the Orchestrator, you must implement three function bodies (`writeArgs`, `readArgs`, `readRet`) to drive the Test Executor (TE). These functions will write input arguments to registers/memory, read modified arguments after execution, and read the return value, respectively"},
                {"role": "user", "content": content},
            ],
            max_tokens=1024,
            stream=False
        )

        content = response.choices[0].message.content

        res = json.loads(re.sub(r"^```json\s*|\s*```$", "", content, flags=re.MULTILINE))

        return 0, res
    except Exception as e:
        return 0, {}

def param_slice(pseudo: str, arg_names: List[str]) -> Dict[str, str]:
    res: Dict[str, List[str] | str] = {}
    lines = pseudo.split("\n")
    begin_body = False
    for line in lines:
        if line.find('{') != -1:
            begin_body = True
        if not begin_body:
            continue
        for arg_name in arg_names:
            if arg_name in line:
                res.setdefault(arg_name, []).append(line.strip())
    for k, v in res.items():
        res[k] = '\n'.join(v)

    return res

def tg_materializer_process(dy: Dict, all_funcs: Dict, logger: logging.Logger, tolerance: int = 3):
    for offset, info_list in dy.items():
        timer = Timer()
        timer.start()
        info = info_list[-1]
        sr = info['sr']
        if "tg_orchestrator" not in info:
            logger.info(f"[TG] WARNING: NOT DESIGNED")
            continue
        test_cases = info['tg_orchestrator']['test_cases']
        a = {}
        impl_list = info.setdefault('tg_materializer', [{"impl_version": 0, "exec_version": 0} for _ in test_cases])
        for i, tc in enumerate(test_cases):
            if impl_list[i]['impl_version'] > impl_list[i]['exec_version'] or impl_list[i].get("exec", {"success": False})['success']:
                logger.warning(f"[TG] WARNING: PASS, offset = {offset}")
                continue
            if impl_list[i]['impl_version'] >= tolerance:
                logger.warning(f"[TG] WARNING: REACH TOLERANCE, offset = {offset}")
                continue
            if offset not in all_funcs:
                logger.error(f"[TG] ERROR: NOT IN ALL_FUNCS, offset = {offset}")
                continue
            pseudo = all_funcs[offset]['pseudo']
            error_info = ""
            if impl_list[i]['impl_version'] > 0 and impl_list[i]['exec'].get('success', True) == False:
                # exec failed
                error_info = impl_list[i]['exec']["error_info"]
            # query
            timer.pause()
            tokens, imp = tg_query_LLM_for_materializer(pseudo, tc, all_funcs[offset]['args'], all_funcs[offset]['ret'], error_info, logger)
            timer.resume()
            timer.stop()
            if not imp:  # fail
                logger.error(f"""[TG] ERROR: offset = {offset}, idx = {i}, test_case = {tc}, imp = {imp}, time = {{"actual": {timer.actual_time},"without_query": {timer.effective_time},"query_count": {timer.pause_count}}}""")
                continue
            logger.info(f"[TG] IMPL: offset = {offset}, idx = {i}, test_case = {tc}, imp = {imp}")
            # save to dy
            impl_list[i]['impl'] = imp
            # update version
            impl_list[i]['impl_version'] += 1
            # save time
            impl_list[i]['time'] = {
                "actual": timer.actual_time,
                "without_query": timer.effective_time,
                "query_count": timer.pause_count
            },


def tg_orchestrator_process(dy: Dict, all_funcs: Dict, logger: logging.Logger):
    for offset, info_list in dy.items():
        timer = Timer()
        timer.start()
        info = info_list[-1]
        sr = info['sr']
        if "tg_orchestrator" in info:
            logger.info(f"[TG] PASS, offset = {offset}")
            continue
        if offset not in all_funcs:
            logger.error(f"[TG] ERROR: NOT IN ALL_FUNCS, offset = {offset}")
            continue
        pseudo = all_funcs[offset]['pseudo']
        arg_names = [arg['name'] for arg in all_funcs[offset]['args']]
        if not arg_names:
            logger.warning(f"[TG] WARNING: NO ARGS, offset = {offset}")
            continue
        slice_res = param_slice(pseudo, arg_names)
        # query
        timer.pause()
        tokens, test_cases = tg_query_LLM_for_orchestrator(sr, pseudo, slice_res, logger)
        timer.resume()
        timer.stop()
        if not isinstance(test_cases, list) or len(test_cases) == 0:
            logger.error(f"""[TG] ERROR: offset = {offset}, test_cases = {test_cases}, time = {{"actual": timer.actual_time,"without_query": timer.effective_time,"query_count": timer.pause_count}}""")
            continue
        logger.info(f"[TG] TEST_CASES: offset = {offset}, test_cases = {test_cases}")
        # save to dy
        info['tg_orchestrator'] = {
            "test_cases": test_cases,
            "time": {
                "actual": timer.actual_time,
                "without_query": timer.effective_time,
                "query_count": timer.pause_count
            },
            "tokens": tokens
        }

def tg_process(project_name: str, mode: str, logger: logging.Logger):
    all_funcs_folder = os.path.join(PROJECTS_FOLDER, project_name, "aligned_call", "all_funcs")
    st_folder = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "static")
    st_files = [file for file in os.listdir(st_folder) if not file.startswith(".") and not file.startswith("cache_")]
    dy_folder = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "tg")
    makedirs_if_necessary(dy_folder)
    for st_file in st_files:
        st_path = os.path.join(st_folder, st_file)
        dy_path = os.path.join(dy_folder, st_file)
        if not os.path.exists(dy_path):
            if mode == 'materializer':
                raise RuntimeError("error mode = materializer")
            with open(st_path, 'r', encoding='utf-8') as fr, open(dy_path, 'w', encoding='utf-8') as fw:
                st = json.load(fr)
                dy = {}
                for offset, info in st.items():
                    dy[offset] = [{
                        "sr": info
                    }]
                json.dump(dy, fw)
    # begin
    dy_files = [file for file in os.listdir(dy_folder) if not file.startswith(".") and not file.startswith("cache_")]
    for dy_file in dy_files:
        dy_path = os.path.join(dy_folder, dy_file)
        all_funcs_path = os.path.join(all_funcs_folder, dy_file)
        dy = {}
        with open(dy_path, 'r', encoding='utf-8') as fdy, open(all_funcs_path, 'r', encoding='utf-8') as faf:
            dy = json.load(fdy)
            all_funcs = json.load(faf)
            if mode == 'orchestrator':
                tg_orchestrator_process(dy, all_funcs, logger)
            else:
                tg_materializer_process(dy, all_funcs, logger)

        with open(dy_path, 'w', encoding='utf-8') as f:
            json.dump(dy, f)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--project_names', nargs='+', help='project_name')
    parser.add_argument("--mode", choices=['orchestrator', 'materializer'])
    args = parser.parse_args()
    project_names = args.project_names
    mode = args.mode

    for project_name in project_names:
        logger = get_logger(f"tg_{project_name}_{mode}", level=logging.INFO)
        logger.info(f"[+]PROJECT BEGIN {project_name}")
        tg_process(project_name, mode, logger)
        logger.info(f"[+]PROJECT END {project_name}")



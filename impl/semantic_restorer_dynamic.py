import json
import logging
import os
import re
from typing import Dict, Set, Tuple, List

import requests
from openai import OpenAI

from utils.cache import PersistentCache
# from executor import executor_exec
# from test_generator import tg_process_one
from utils.timer import Timer
from utils.common_utils import get_logger, convert_origin_to_dwarf_json, makedirs_if_necessary

PROJECTS_FOLDER = "" # TODO replace with actual folder

def sr_query_LLM(
        assembly: List[str],
        pseudo: str,
        callsite_to_callee_str: str,
        callee_facts: Dict[str, Dict[str, str]],
        signature_str: str = None,
        args_info_str: str = None,
        test_case: Dict = None,
        dynamic_feedback_str = None,
        architecture: str = "arm64-v8a"
) -> Dict:
    url = "your url"

    api_key = "your api key"
    client = OpenAI(api_key=api_key, base_url=url)

    split_char = assembly[0].find(":")
    if split_char == -1:
        raise RuntimeError("invalid assembly format")
    so_name = assembly[0][:split_char]

    assembly_extracted_str = ""
    if len(assembly) <= 0:
        assembly_extracted = []
        for c in assembly:
            assembly_extracted.append(c[split_char + 1:])
        assembly_extracted_str = "\n".join(assembly_extracted)

    callee_facts_str = ""
    if callee_facts:
        callee_facts_str = "Semantic information of the called function: Each called function occupies 3 lines, representing respectively: the identifier of the called function (which may be the address or symbol name), the inferred function name, and the comment or functional description of the function:\n"
        for callee, callee_fact in callee_facts.items():
            callee_facts_str += f"{callee}:\n{callee_fact['func_name']}\n{callee_fact['summarization']}"

    test_case_str = json.dumps(test_case)

    content = f"""
Architecture: 
{architecture}
File name: 
{so_name}
Function Signature: 
{signature_str}
Parameters:
{args_info_str}
Decompiled Code:
{pseudo}
{callsite_to_callee_str}
{callee_facts_str}
Execute the function using the following test cases:
{test_case_str}
Analyze its execution information and summarize the following conclusion:
{dynamic_feedback_str}
You should take this conclusion into account to obtain a more accurate function name and summary.

Requirements:
1. Function names should avoid being too generic (e.g., process, handle) and should reflect specific business or algorithm semantics
2. Comments should be accurate, concise, and readable, avoiding redundancy or irrelevant information
3. If certain parameters or logic cannot be determined, clearly state the speculation or unknowns in the comments
4. If the above decompiled code contains "tpidr_el0" and "__stack_chk_fail()", please ignore them as they are caused by partial decompilation failure in Ghidra

An output example as follows:
{{
    "func_name": "pow_int",
    "summarization": "This function calculates the 2nd power of parameter 1, where param_1 is of int type, representing the base, and param_2 is also of int type, representing the power.",
}}
    """

    try:
        response = client.chat.completions.create(
            model="deepseek-r1",
            messages=[
                {"role": "system",
                 "content": "You are an expert in binary reverse analysis, responsible for analyzing static and dynamic program semantic information.\nYou need to perform semantic understanding and naming of a binary function. The input includes function's architecture, the containing so file, function signature, parameter details, optional disassembled code, decompiled pseudo-C code, call relationships, and semantic information of called functions. The goal is to generate accurate and readable function comments (including explanations for each parameter) and produce a semantically appropriate function name"},
                {"role": "user", "content": content},
            ],
            max_tokens=1024,
            stream=False
        )

        content = response.choices[0].message.content

        res = json.loads(re.sub(r"^```json\s*|\s*```$", "", content, flags=re.MULTILINE))

        return res
    except Exception as e:
        raise RuntimeError(f"query LLM error:{res}")


def format_args(args_info) -> str:
    if len(args_info) == 0:
        return "no args"
    else:
        res = []
        for arg in args_info:
            res.append(f"{arg['name']}'s type is {arg['type']}({arg['width']}B), store at {arg['storage']}")
        return "\n".join(res)

def format_ret(ret_info) -> str:
    if ret_info['type'] == 'void':
        return 'return type is void'
    else:
        if ret_info['width'] > 0 and ret_info['storage']:
            return f"return type is {ret_info['type']}({ret_info['width']}B), store at {ret_info['storage']}"
        else:
            return ret_info['type']

def sr_do_process_dynamic(
        offset: str,
        cache: PersistentCache,
        path: Set[str],
        project_name: str,
        so_name: str,
        target_offset_map: Dict[str, str],
        all_funcs: Dict,
        call_relation: Dict[str, Dict[str, Dict[str, Set[str]]]],
        call_align_info: Dict[str, Dict[str, str]],
        test_cases: Dict,
        ev: Dict,
        iter: int,
        logger: logging.Logger,
        timer: Timer,
        use_call_relation: bool = True, # ablation study
        arch_info: str = "arm64-v8a"
) -> Tuple[bool, Dict[str, str | Dict]]:
    if offset not in all_funcs:
        return True, {}
    if offset not in call_align_info:
        logger.warning(f"[SR] WARNING, offset={offset}, NOT IN CALL_ALIGN_INFO")
        return True, {}
    if cache.has_key(offset) and cache.get(offset):
        return True, cache.get(offset)
    if offset in path:
        logger.warning(f"[SR] WARNING, offset={offset}, RECURSIVE")
        return True, {}
    path.add(offset)

    callee_facts: Dict[str, Dict[str, str | Dict]] = {}
    # callsite to callee info
    callsite_to_callee_str = ""
    if use_call_relation and offset in call_relation:
        for callsite, callee_set in call_relation[offset].get('INTERNAL', {}).items(): # 没有则不处理
            for callee in callee_set:
                key = f"FUN_{callee}"
                if key in callee_facts:
                    continue
                llm_success, callee_fact = sr_do_process_dynamic(callee, cache, path, project_name, so_name, target_offset_map, all_funcs, call_relation, call_align_info, None, None, 0, logger, timer)
                if callee_fact:
                    callee_facts[key] = callee_fact

            if callsite not in call_align_info[offset]:
                continue
            if not callee_set:
                tmp_str = ""
            else:
                tmp_str = f"\nexpression {{{call_align_info[offset][callsite].strip()}}} may call: "
                for callee in callee_set:
                    key = f"FUN_{callee}"
                    tmp_str += f"{key},"
                tmp_str = tmp_str.rstrip(',')
            # 拼接
            callsite_to_callee_str += '\n' + tmp_str
    if callsite_to_callee_str:
        callsite_to_callee_str = "This function calls the corresponding function through the following call statement:\n" + callsite_to_callee_str


    info = all_funcs[offset]
    assembly_str = info['assembly']
    pseudo = info['pseudo']
    signature = info['signature']
    args_info_str = format_args(info['args'])
    ret_info_str = format_ret(info['ret'])

    timer.pause()
    response = sr_query_LLM(assembly_str, pseudo, callsite_to_callee_str, callee_facts, signature, args_info_str, test_cases[offset], ev[iter-1]['feedback'], architecture=arch_info)
    timer.resume()

    facts: Dict[str, str | Dict] = response

    logger.info(f"======SR:{offset}")
    cache.set(offset, facts)
    return True, facts

def sr_process_dynamic(
        project_name: str,
        so_name: str,
        logger: logging.Logger,
        use_history: bool = True,
        is_load_json: bool = False,
        propagate_error: bool = True,
        use_call_relation: bool = True,
        iter: int = 1,
        arch_info: str = "arm64-v8a"
):
    """处理指定项目中的指定so_name"""
    aligned_gt_path = os.path.join(PROJECTS_FOLDER, project_name, "aligned_ground_truth",
                                   convert_origin_to_dwarf_json(so_name))
    target_offset_map: Dict[str, str] = {}
    with open(aligned_gt_path, 'r', encoding='utf-8') as f:
        dt = json.load(f)
        for name, info in dt.items():
            offset = info['function_offset']['start']
            target_offset_map[offset] = name
    all_funcs = {}
    with open(os.path.join(PROJECTS_FOLDER, project_name, "aligned_call", "all_funcs", f"{so_name}.json"), 'r',
              encoding='utf-8') as f:
        all_funcs = json.load(f)
    call_relation = {}
    with open(os.path.join(PROJECTS_FOLDER, project_name, "call_relation", f"{so_name}.json"), 'r',
              encoding='utf-8') as f:
        call_relation = json.load(f)
    with open(os.path.join(PROJECTS_FOLDER, project_name, "aligned_call", "aligned", f"{so_name}.json"), 'r',
              encoding='utf-8') as f:
        call_align_info = json.load(f)

    with open(os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "ev", f"{so_name}.json"), 'r', encoding='utf-8') as f:
        ev = json.load(f)
    with open(os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "tg", f"{so_name}.json"), 'r',encoding='utf-8') as f:
        test_cases = json.load(f)

    if use_call_relation:
        res_folder = os.path.join(PROJECTS_FOLDER, project_name, "res", "self")
    else:
        res_folder = os.path.join(PROJECTS_FOLDER, project_name, "res", "self_wo_call")
    makedirs_if_necessary(res_folder)
    static_res_path = os.path.join(res_folder, "static", f"{so_name}.json")
    cache_path = os.path.join(res_folder, "static", f"cache_{so_name}.json")
    makedirs_if_necessary(os.path.dirname(static_res_path))
    if use_call_relation:
        folder = "self_dynamic"
    else:
        folder = "self_dynamic_wo_call"
    cache = PersistentCache(db_name=project_name, table_name=so_name[:-3].replace('.', '_'), folder=folder,use_history=use_history)
    if use_history and is_load_json and os.path.exists(cache_path):
        logger.info(f"import json from {cache_path}")
        cache.import_from_json(cache_path)
    static_res = {}
    for target_offset in target_offset_map:
        if use_history and cache.has_key(target_offset):
            logger.info(f"[SR] PASS, offset = {target_offset}")
            static_res[target_offset] = cache.get(target_offset)
            with open(static_res_path, 'w', encoding='utf-8') as f:
                json.dump(static_res, f)
            continue
        path = set()
        try:
            timer = Timer()
            timer.start()
            llm_success, facts = sr_do_process_dynamic(target_offset, cache, path, project_name, so_name,
                                                      target_offset_map, all_funcs, call_relation, call_align_info,
                                                      test_cases, ev, iter, logger, timer, use_call_relation=use_call_relation,
                                                      arch_info=arch_info)
            timer.stop()
            if facts:
                logger.info(
                    f"[SR] FACTS, offset={target_offset}, func_name={facts['func_name']}, summarization={facts['summarization']}")
                static_res[target_offset] = {
                    "func_name": facts['func_name'],
                    "summarization": facts['summarization'],
                    "reference": dt[target_offset_map[target_offset]]['func_name-src']['name'],
                    "time": {
                        "actual": timer.actual_time,
                        "without_query": timer.effective_time,
                        "query_count": timer.pause_count
                    }
                }
                cache.set(target_offset, static_res[target_offset])
                with open(static_res_path, 'w', encoding='utf-8') as f:
                    json.dump(static_res, f)
            else:
                logger.warning(f"[SR] WARNING, offset={target_offset}, EMPTY")
        except Exception as e:
            if propagate_error:
                cache.delete(target_offset)
            logger.error(f"[SR] Error {target_offset}, message = {str(e)}")
    cache.export_to_json(cache_path)
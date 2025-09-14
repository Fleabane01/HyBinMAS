import argparse
import json
import logging
import os
import re
from typing import Dict, List

from openai import OpenAI

from utils.common_utils import get_logger

logger = get_logger(f"execution_validator.py", level=logging.INFO)
PROJECTS_FOLDER = "" # TODO replace with actual folder

def ev_query_LLM(
        arch: str,
        file_name: str,
        predicted_func_name: str,
        predicted_summarization: str,
        test_cases: Dict,
        exec_info: List
):
    url = "your url"

    api_key = "your api key"
    client = OpenAI(api_key=api_key, base_url=url)

    success_test_cases = [{
        **test_cases[idx],
        **exec_info
    }for idx, item in enumerate(exec_info) if item['success']]
    fail_test_cases = [{
        **test_cases[idx],
        **exec_info
    } for idx, item in enumerate(exec_info) if not item['success']]

    success_test_cases_str = json.dumps(success_test_cases)
    fail_test_cases_str = json.dumps(fail_test_cases)

    content = f"""
Function architecture
{arch}
File name: 
{file_name}
Predicted Function Name: 
{predicted_func_name}
Predicted Summarization: 
{predicted_summarization}
Test Cases Passed: 
{success_test_cases}
Test Cases Failed: 
{fail_test_cases}

Requirements:
1. For successful cases,If they match, mark the case as **passed**.If they differ, summarize the mismatches clearly, focusing on differences that may influence semantic understanding.
2. For failed cases, analyze the error messages and infer the most likely cause of failure. Summarize in a structured, concise format.
3. Avoid including irrelevant or verbose runtime details; focus on information that help SR improve semantic accuracy and precision.
4. Output should be in natural language, well-structured, and suitable for direct input into SR for next refinement iteration
"""

    try:
        response = client.chat.completions.create(
            model="deepseek-r1",
            messages=[
                {"role": "system",
                 "content": "You are an expert in dynamic execution analysis, responsible for  validating execution results.\nYour task is to analyze the execution results of binary functions under specific test cases, validate them against expected outputs, and summarize the findings into concise, structured natural language feedback. The purpose is to assist the Semantic Restorer (SR) in refining the function's semantic summary and name. You will receive both successful and failed execution cases, and you must process them respectively."},
                {"role": "user", "content": content},
            ],
            max_tokens=1024,
            stream=False
        )

        content = response.choices[0].message.content

        res = content.strip()

        return res
    except Exception as e:
        raise RuntimeError(f"query LLM error:{res}")

def ev_process(project_name: str, so_name: str, iter: int) -> Dict:
    tg_path = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "tg", f"{so_name}.json")
    st_path = os.path.join(PROJECTS_FOLDER, project_name, "res", "self", "st", f"{so_name}.json")
    with open(tg_path, 'r', encoding='utf-8') as f:
        tg = json.load(f)
    with open(st_path, 'r', encoding='utf-8') as f:
        st = json.load(f)

    ev_path = os.path.join(PROJECTS_FOLDER, project_name, "res", "ev", f"{so_name}.json")
    ev = {}
    with open(ev_path, 'r', encoding='utf-8') as f:
        ev = json.load(f)

    all_funcs = {}
    with open(os.path.join(PROJECTS_FOLDER, project_name, "aligned_call", "all_funcs", f"{so_name}.json"), 'r', encoding='utf-8') as f:
        all_funcs = json.load(f)

    for offset, info in tg.items():
        if len(info) < iter:
            logger.info("PASS, iter done")
            continue
        if offset in ev and len(ev[offset]) >= iter:
            continue
        test_cases = info[iter-1]['tg_orchestrator']['test_cases']
        exec = [it['exec'] for it in info[iter-1]['tg_materializer']]
        feedback = ev_query_LLM("arm64-v8a", so_name, st[offset]['func_name'], st[offset]['summarization'], test_cases, exec)
        if not feedback:
            continue
        ev.setdefault(offset, []).append({
            "feedback": feedback,
        })

    with open(ev_path, 'w', encoding='utf-8') as f:
        json.dump(ev, f)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--p', help='project_name')
    parser.add_argument('--f', help='so_name')
    parser.add_argument('--iter', help='iter')
    args = parser.parse_args()
    project_name = args.p
    so_name = args.f
    iter = int(args.iter)
    ev_process(project_name, so_name, iter)
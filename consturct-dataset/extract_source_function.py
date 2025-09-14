import argparse
import json
import logging
import os
import time
from fileinput import filename
from turtledemo.sorting_animate import start_ssort
from typing import Dict, Any, Set

import requests
import tree_sitter
import tree_sitter_cpp
from tree_sitter import Language, Parser
import pyghidra

from utils.common_utils import get_logger, makedirs_if_necessary

pyghidra.start()

PROJECTS_FOLDER = "" # TODO replace with actual folder
SOURCE_FOLDER = "" # todo replace with actual folder containing source code
ANDROID_SDK_FOLDER = "" # TODO replace with actual folder containing Android SDK

CPP_LANGUAGE = Language(tree_sitter_cpp.language())
cpp_parser = Parser(CPP_LANGUAGE)

logger = get_logger("extract_source_function.py", level=logging.ERROR)

ERROR = 0
CUSTOM = 1
STD = 2
THIRD_PARTY = 3
REMOTE_COMPILED = 4




def extract_cpp_function(
        # metadata: Dict,
        project_name,
        filename,
        funcname,
        filepath: str,
        start_line: int
) -> (Dict[str, str] | None, int):

    filepath = os.path.abspath(filepath)
    source_folder = os.path.join(SOURCE_FOLDER, project_name)

    if not os.path.exists(filepath):
        logger.error(f"[+]FILE ERROR {project_name} -> {filename} -> {funcname}: source code not existed in local machine ({filepath}), may be compiled at remote")
        return None, REMOTE_COMPILED

    with open(filepath, 'r', encoding='utf-8') as file:
        code = file.read()

    tree = cpp_parser.parse(bytes(code, 'utf8'))

    root_node = tree.root_node

    adjusted_start_line = start_line - 1

    res = {}
    def find_function(node: tree_sitter.Node) -> tree_sitter.Node | None:
        if node.type == 'function_definition':
            if node.start_point[0] <= adjusted_start_line <= node.end_point[0]:
                func_name, is_operator = extract_function_name(node)
                if not func_name:
                    logger.error(f"[+]FUNCTION ERROR {project_name} -> {filename} -> {funcname} : couldn't find func_name")
                    return None
                res['func_name-src'] = {
                    'name': func_name,
                    'is_operator': is_operator
                }
                return node

        for child in node.children:
            result = find_function(child)
            if result:
                return result

        return None

    def find_identifier(node: tree_sitter.Node) -> tree_sitter.Node | None:
        if node.type == 'identifier':
            return node
        ret = None
        for child in node.children:
            nd = find_identifier(child)
            if nd is not None:
                if ret:
                    logger.error(f"[+]FUNCTION WARNING {project_name} -> {filename} -> {funcname} 2 identifiers")
                ret = nd
        return ret

    def find_by_type(node: tree_sitter.Node, _type: str) -> tree_sitter.Node:
        if node.type == _type:
            return node
        ret = None
        for child in node.children:
            nd = find_by_type(child, _type)
            if not nd:
                break
        return ret

    def extract_function_name(node: tree_sitter.Node) -> (str, bool):
        if node.type == 'function_declarator':
            ret = ""
            is_operator = False
            for child in node.children:
                if child.grammar_name == 'identifier':
                    ret = code[child.start_byte:child.end_byte]
                    break
                elif child.type == 'qualified_identifier':
                    nd = find_identifier(child)
                    if nd is not None:
                        ret = code[nd.start_byte:nd.end_byte]
                        break
                    nd = find_by_type(child, 'operator_name')
                    if nd is not None:
                        ret = code[nd.start_byte:nd.end_byte]
                        break
                elif child.type == 'operator_name':
                    ret = code[child.start_byte:child.end_byte]
                    is_operator = True
                    break


            return ret, is_operator

        for child in node.children:
            name, is_operator = extract_function_name(child)
            if name:
                return name, is_operator

        return "", False

    function_node = find_function(root_node)
    if not function_node:
        logger.error(f"[+]FUNCTION ERROR {project_name} -> {filename} -> {funcname} : couldn't find function node")
        return None, ERROR

    function_code = code[function_node.start_byte:function_node.end_byte]
    res['func_body-src'] = function_code

    if filepath.startswith(os.path.abspath(ANDROID_SDK_FOLDER)):
        logger.warning(f"[+]FILE WARNING {project_name} -> {filename} -> {funcname}: std cpp {ANDROID_SDK_FOLDER}, {filepath}")
        return res, STD

    if not filepath.startswith(source_folder):
        logger.warning(f"[+]FILE WARNING {project_name} -> {filename} -> {funcname}: not custom cpp, but can still be used {source_folder}, {filepath}")
        return res, THIRD_PARTY

    return res, CUSTOM


def process_aligned_src_file(project_visited: Set[str], project_name: str, filename: str, filepath: str) -> (Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]):
    with open(filepath, 'r', encoding='utf-8') as f:
        aligned_src = json.load(f)
    std_res = {}
    res = {}
    visited: Set[str] = set()
    for name, info in aligned_src.items():
        logger.info(f"[+]FUNCTION BEGIN {project_name} -> {filename} -> {name}")
        cpp_file_path = info['filename-src']
        cpp_func_start_line = info['line_start-src']
        key = filename + str(cpp_func_start_line)
        if key in visited:
            logger.warning(f"[+]FUNCTION FILTERED {project_name} -> {filename} -> {name} : repeated line_num, may be template function")
            continue
        visited.add(key) # visit

        cpp_func_info, category = extract_cpp_function(project_name, filename, name, cpp_file_path, cpp_func_start_line)
        if not cpp_func_info:
            logger.warning(f"[+]FUNCTION FILTERED {project_name} -> {filename} -> {name} : couldn't get source info")
            continue

        project_key = cpp_func_info['func_name-src']['name'] + ":" + cpp_file_path
        if project_key in project_visited:
            logger.error(f"[+]FUNCTION FILTERED {project_name} -> {filename} -> {name} : cross file duplication: {project_key}")
            continue
        project_visited.add(project_key) # visit

        if category == STD:
            std_res[name] = {**info,
                             **cpp_func_info
                             }
            continue
        # merge
        res[name] = {**info,
                     **cpp_func_info
                     }
        logger.info(f"[+]FUNCTION END {project_name} -> {filename} -> {name}")

    return res, std_res


def process(project_name: str):
    # aligned_src
    aligned_src_folder = os.path.join(PROJECTS_FOLDER, project_name, "aligned_src")
    aligned_src_files = [name for name in os.listdir(aligned_src_folder) if not name.startswith(".")]

    aligned_sgt_folder = os.path.join(PROJECTS_FOLDER, project_name, "aligned_ground_truth")
    makedirs_if_necessary(aligned_sgt_folder)

    project_visited = set()

    for aligned_src_file in aligned_src_files:
        logger.info(f"[+]FILE BEGIN {project_name} -> {aligned_src_file}")
        aligned_extract, std_res = process_aligned_src_file(project_visited, project_name, aligned_src_file, os.path.join(aligned_src_folder, aligned_src_file))

        if len(std_res) > 0:
            std_path = os.path.join(PROJECTS_FOLDER, project_name, "aligned_extract_std", aligned_src_file)
            if not os.path.exists(os.path.dirname(std_path)):
                os.makedirs(os.path.dirname(std_path), exist_ok=True)
            with open(std_path, 'w', encoding='utf-8') as f:
                json.dump(std_res, f)

        if len(aligned_extract) == 0:
            logger.warning(f"[+]FILE FILTERED {project_name} -> {aligned_src_file} : aligned_extract is empty")
            continue
        # save
        aligned_sgt_path = os.path.join(aligned_sgt_folder, aligned_src_file)
        with open(aligned_sgt_path, 'w', encoding='utf-8') as f:
            json.dump(aligned_extract, f)
        logger.info(f"[+]FILE END {project_name} -> {aligned_src_file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--project_names', nargs='+', help='project_names?')
    args = parser.parse_args()
    project_names = args.project_names

    if len(project_names) == 0:
        project_names = [name for name in os.listdir(PROJECTS_FOLDER) if not name.startswith(".")]
    print(project_names)
    for project_name in project_names:
        logger.info(f"[+]PROJECT BEGIN {project_name}")
        process(project_name)
        logger.info(f"[+]PROJECT END {project_name}")

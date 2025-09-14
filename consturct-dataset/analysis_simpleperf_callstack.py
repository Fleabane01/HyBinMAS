import argparse
import json
import logging
import os
from typing import Dict, List,Tuple

from utils.common_utils import get_logger, makedirs_if_necessary, convert_dwarf_json_to_origin

logger = get_logger('analysis_simpleperf_callstack.py', level=logging.INFO)

SIMPLEPERF_DATA_FOLDER = "" # TODO replace with actual folder
PROJECTS_FOLDER = "" # TODO replace with actual folder


def parse_single_callstack_block(lines: List[str]):
    header = lines[0]
    frames = []
    for line in lines[1:]:
        parts = line.strip().split(' ', 2)
        if len(parts) < 3:
            continue
        _, symbol_offset, lib_path = parts
        lib_path = lib_path.strip('()')
        frames.append({
            'symbol_offset': symbol_offset,
            'library_path': lib_path
        })
    return {'header': header, 'frames': frames}

def is_hex_string(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def update_result_with_sample(sample, so_names_set, result: Dict[str, List[List[str]]]):
    frames = sample['frames']
    current_so = None
    current_segment: List[str] = []

    for frame in frames:
        symbol_offset = frame.get('symbol_offset', '')
        so_name, offset = '', ''
        if '[+' in symbol_offset:
            try:
                so_name, offset = symbol_offset.strip().split('[+')
                offset = offset[:-1].zfill(8)
                if not is_hex_string(offset):
                    so_name, offset = '', ''
            except Exception:
                so_name, offset = '', ''

        if so_name in so_names_set:
            print(so_name, offset)
            if current_so == so_name or current_so is None:
                current_segment.append(offset)
                current_so = so_name
            else:
                if current_segment:
                    if current_so not in result:
                        result[current_so] = []
                    current_segment.reverse()
                    result[current_so].append(current_segment)
                current_segment = [offset]
                current_so = so_name
        else:
            if current_segment:
                if current_so not in result:
                    result[current_so] = []
                current_segment.reverse()
                result[current_so].append(current_segment)
            current_segment = []
            current_so = None

    if current_segment and current_so:
        if current_so not in result:
            result[current_so] = []
        current_segment.reverse()
        result[current_so].append(current_segment)


def analysis_single_file(res: Dict[str, List[List[str]]], callstack_file_path: str, so_names: list):
    so_names_set = set(so_names)

    with open(callstack_file_path, 'r', encoding='utf-8') as f:
        block_lines = []
        for line in f:
            if line.strip() == '':
                if block_lines:
                    sample = parse_single_callstack_block(block_lines)
                    update_result_with_sample(sample, so_names_set, res)
                    block_lines = []
            else:
                block_lines.append(line.rstrip('\n'))

        if block_lines:
            sample = parse_single_callstack_block(block_lines)
            update_result_with_sample(sample, so_names_set, res)


def analysis(project_name: str):
    align_extract_folder = os.path.join(PROJECTS_FOLDER, project_name, "aligned_extract")
    so_names = [convert_dwarf_json_to_origin(name) for name in os.listdir(align_extract_folder) if not name.startswith(".")]

    dynamic_folder = os.path.join(PROJECTS_FOLDER, project_name, "aligned_call", "dynamic_record")
    makedirs_if_necessary(dynamic_folder)

    callstack_folder = os.path.join(SIMPLEPERF_DATA_FOLDER, project_name, "callstack")
    callstack_files = sorted([name for name in os.listdir(callstack_folder) if not name.startswith(".")])
    res: Dict[str, List[List[str]]] = {}
    for callstack_file in callstack_files:
        callstack_file_path = os.path.join(callstack_folder, callstack_file)
        analysis_single_file(res, callstack_file_path, so_names)
        for so_name, info in res.items():
            with open(os.path.join(dynamic_folder, f"{so_name}.json"), 'w', encoding='utf-8') as f:
                json.dump(info, f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--project_names', nargs='+', help='project_names?')
    args = parser.parse_args()
    project_names = args.project_names

    if len(project_names) == 0:
        project_names = os.listdir(PROJECTS_FOLDER)
    print(project_names)

    for project_name in project_names:
        logger.info(f"[+]PROJECT BEGIN {project_name}")
        analysis(project_name)
        logger.info(f"[+]PROJECT END {project_name}")
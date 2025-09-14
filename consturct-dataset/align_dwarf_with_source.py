import argparse
import json
import logging
import os
from typing import Any, Dict

from elftools.elf.elffile import ELFFile

from utils.common_utils import get_logger, makedirs_if_necessary

from elftools.elf.elffile import ELFFile

# Dataset prefix
PROJECTS_FOLDER = "" # TODO replace with actual folder


logger = get_logger('align_dwarf_with_source.py', level=logging.ERROR)

def func_offset_to_virtual_address(elf, func_offset: str):
    func_offset = int(func_offset, 16)
    for segment in elf.iter_segments():
        seg_offset = segment['p_offset']
        seg_filesz = segment['p_filesz']
        seg_vaddr = segment['p_vaddr']
        if seg_offset <= func_offset < seg_offset + seg_filesz:
            vaddr = seg_vaddr + (func_offset - seg_offset)
            return vaddr
    return None

def get_dwarf_cache(so_path) -> Dict[int, Any]:
    with open(so_path, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return {}

        dwarf_cache = {}

        dwarf_info = elf.get_dwarf_info()
        for CU in dwarf_info.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag == 'DW_TAG_subprogram':
                    low_pc_attr = DIE.attributes.get('DW_AT_low_pc')
                    if low_pc_attr is None:
                        continue

                    low_pc = low_pc_attr.value

                    file_name = None
                    decl_file_attr = DIE.attributes.get('DW_AT_decl_file')
                    if decl_file_attr:
                        file_index = decl_file_attr.value
                        lineprog = dwarf_info.line_program_for_CU(CU)
                        if lineprog and 0 < file_index <= len(lineprog['file_entry']):
                            file_entry = lineprog['file_entry'][file_index - 1]
                            file_name = file_entry.name.decode('utf-8')
                            dir_index = file_entry.dir_index
                            if dir_index != 0:
                                dir_name = lineprog['include_directory'][dir_index - 1].decode('utf-8')
                                file_name = f"{dir_name}/{file_name}"

                    decl_line_attr = DIE.attributes.get('DW_AT_decl_line')
                    line_start = decl_line_attr.value if decl_line_attr else None

                    if file_name is None or line_start is None:
                        continue

                    dwarf_cache[low_pc] = {
                        'filename-src': file_name,
                        'line_start-src': line_start,
                    }

        return dwarf_cache


def align_single_so(project_name, filename, so_path, func_map: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    dwarf_cache = get_dwarf_cache(so_path)
    with open(so_path, 'rb') as f:
        elf = ELFFile(f)
        res = {}
        for func_name, func_info in func_map.items():
            logger.info(f"[+]FUNCTION BEGIN {project_name} -> {filename} -> {func_name}")
            if not func_info or not isinstance(func_info, dict):
                logger.error(f"[+]FUNCTION ERROR {project_name} -> {filename} -> {func_name} filtered: not a dict")
                continue
            func_offset = func_info['function_offset']['start']

            func_vaddr = func_offset_to_virtual_address(elf, func_offset)
            if func_vaddr is None:
                logger.error(f"FUNCTION ERROR {project_name} -> {filename} -> {func_name}: file offset 0x{func_offset} not in any loadable segment.")
                continue

            src_metadata = dwarf_cache.get(func_vaddr, None)
            if src_metadata is None:
                logger.info(f"[+]FUNCTION FILTERED {project_name} -> {filename} -> {func_name} : couldn't get src_metadata")
                continue
            res[func_name] = {**func_info, **src_metadata}
            logger.info(f"[+]FUNCTION END {project_name} -> {filename} -> {func_name}")

    return res

def extract_so_file_name(filename: str) -> str:
    if not filename.endswith(".json"):
        raise Exception(filename)
    idx = filename.rfind(".json")
    return filename[:idx]

def align(project_name: str):
    unstripped_folder = os.path.join(PROJECTS_FOLDER, project_name, "app-release-dwarf", "lib", "arm64-v8a")
    unstripped_files = sorted(os.listdir(unstripped_folder))
    collected_folder = os.path.join(PROJECTS_FOLDER, project_name, "collected")
    collected_files = sorted(os.listdir(collected_folder))

    aligned_folder = os.path.join(PROJECTS_FOLDER, project_name, 'aligned_src')
    makedirs_if_necessary(aligned_folder)
    for collected_file in collected_files:
        unstripped_file = extract_so_file_name(collected_file)
        logger.info(f"[+]FILE BEGIN {project_name} -> {unstripped_file}")
        so_path = os.path.join(PROJECTS_FOLDER, project_name, unstripped_folder, unstripped_file)
        collected_path = os.path.join(collected_folder, f"{unstripped_file}.json")
        with open(collected_path, 'r', encoding='utf-8') as f:
            collected = json.load(f)
        aligned_src = align_single_so(project_name, collected_file, so_path, collected)
        if len(aligned_src) == 0:
            logger.info(f"[+]FILE FILTERED {project_name} -> {unstripped_file} : aligned_src is empty, can't not find source")
            continue
        aligned_path = os.path.join(aligned_folder, f"{unstripped_file}.json")
        with open(aligned_path, 'w', encoding='utf-8') as f:
            json.dump(aligned_src, f)
        logger.info(f"[+]FILE END {project_name} -> {unstripped_file}")

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
        align(project_name)
        logger.info(f"[+]PROJECT END {project_name}")

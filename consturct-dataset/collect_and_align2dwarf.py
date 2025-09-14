import argparse
import json
import logging
import pyghidra

from utils.common_utils import get_logger, makedirs_if_necessary
from utils.decompile_utils import update_func_by_decomp, get_args, get_ret

pyghidra.start()
from ghidra.program.model.pcode import HighFunction
import os
import shutil
from typing import Dict, Optional, Any, Tuple, List
from ghidra.program.model.listing import ParameterImpl, Program, StackFrame, Variable, ReturnParameterImpl, Function, \
    CodeUnit
from ghidra.program.model.symbol import SourceType, ReferenceManager
from ghidra.app.decompiler import DecompInterface, DecompileResults
from ghidra.util.task import TaskMonitor, ConsoleTaskMonitor

logger = get_logger('collect_and_align2dwarf.py', level=logging.WARNING)

# Dataset prefix
PROJECTS_FOLDER = "" # TODO replace with actual folder
# Ghidra project folder
GHIDRA_PROJECT_FOLDER = "" # TODO replace with actual folder


def get_data_type_info(metadata: Dict, var: Variable, is_arg: bool, ordinal: int, ref_manager: ReferenceManager) -> Dict:
    # variable name and type
    varname = var.getName()
    type_object = var.getDataType()
    type_name = type_object.getName()

    # get to what ever the pointer is pointing to
    ptr_bool = False
    try:
        for _ in range(type_name.count('*')):
            type_object = type_object.getDataType()
            type_name = type_object.getName()
            ptr_bool = True
    except Exception as e:
        logger.warning(f"resolve pointer data type error: {str(e)}")
        pass

    # if a typedef, get the primitive type definition
    try:
        type_object = type_object.getBaseDataType()
        type_name = type_object.getName()
    except Exception as e:
        logger.warning(f"resolve type definition error: {str(e)}")
        pass

    is_struct = False
    is_union = False
    if len(str(type_object).split('\n')) >= 2:
        if 'Struct' in str(type_object).split('\n')[2]:
            is_struct = True
        elif 'Union' in str(type_object).split('\n')[2]:
            is_union = True

    try:
        type_object.getCount()
        is_enum = True
    except:
        is_enum = False

    if ptr_bool:
        type_name += ' *'

    metadata[varname] = {'type': str(type_name), 'addresses': [],
                  'agg': {'is_enum': is_enum, 'is_struct': is_struct, 'is_union': is_union}}

    locs = ref_manager.getReferencesTo(var)
    for loc in locs:
        metadata[varname]['addresses'].append(loc.getFromAddress().toString())

    if var.isRegisterVariable():
        metadata[varname]['register'] = [reg.getName() for reg in var.getRegisters()]
    if var.isStackVariable():
        metadata[varname]['stack_offset'] = var.getStackOffset()
    if is_arg:
        metadata[varname]['ordinal'] = ordinal

    return metadata


def process_stripped_so(file_path: str, project_name: str) -> Dict[str, Dict[str, Any]]:
    with pyghidra.open_program(file_path, project_location=GHIDRA_PROJECT_FOLDER,
                               project_name=project_name, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()

        function_manager = program.getFunctionManager()
        symbol_table = program.getSymbolTable()
        listing = program.getListing()
        ref_manager = program.getReferenceManager()

        decompiler = DecompInterface()
        decompiler.openProgram(program)

        new_base_addr = flat_api.toAddr(0x0)
        program.setImageBase(new_base_addr, True)

        res = {}


        filename = os.path.basename(file_path)

        function = flat_api.getFirstFunction()
        while function is not None:
            funcname = function.name
            logger.info(f"[+]FUNCTION BEGIN {project_name} -> {os.path.basename(file_path)}->{funcname}")
            if not funcname.startswith("FUN_"):
                logger.info(f"[+]FUNCTION FILTERED {project_name} -> {os.path.basename(file_path)} -> {funcname} : function not begin with FUN_")
                function = flat_api.getFunctionAfter(function)
                continue

            try:
                decomp_result = decompiler.decompileFunction(function, 60, ConsoleTaskMonitor())
                decompiled_function = decomp_result.getDecompiledFunction().getC()
                high_func = decomp_result.getHighFunction()
                update_func_by_decomp(high_func, program)
            except Exception as e:
                logger.error(f"[+]FUNCTION ERROR {project_name} -> {os.path.basename(file_path)} -> {funcname} :decompile failed {str(e)}")
                function = flat_api.getFunctionAfter(function)
                continue

            addrSet = function.getBody()
            codeUnits = listing.getCodeUnits(addrSet, True)

            assembly = []
            for codeUnit in codeUnits:
                instruction = codeUnit.toString()
                assembly.append(f"{filename}:[+0x{codeUnit.getMinAddress()}] {instruction}")

            args = get_args(high_func)
            signature = function.getSignature().getPrototypeString()
            ret = get_ret(high_func)

            res[str(function.getEntryPoint())] = {
                "assembly": assembly,
                "pseudo": decompiled_function,
                "args": args,
                "function_offset": {
                    'start': str(function.getEntryPoint()),
                    'end': str(function.getBody().getMaxAddress()),
                },
                "signature": signature,
                "ret": ret
            }
            logger.info(f"[+]FUNCTION END {project_name} -> {os.path.basename(file_path)} -> {funcname}")
            function = flat_api.getFunctionAfter(function)

    return res


def process_unstripped_so(stripped_info: Dict[str, Dict[str, Any]], file_path: str, project_name: str) -> Dict[str, Dict[str, Any]]:
    res = {}
    with pyghidra.open_program(file_path, project_location=GHIDRA_PROJECT_FOLDER, project_name=project_name, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        function_manager = program.getFunctionManager()
        symbol_table = program.getSymbolTable()
        listing = program.getListing()
        ref_manager = program.getReferenceManager()
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        new_base_addr = flat_api.toAddr(0x0)
        program.setImageBase(new_base_addr, True)
        for offset, stripped_func in stripped_info.items():
            func = flat_api.getFunctionAt(flat_api.toAddr(offset))
            if not func:
                continue
            filename = os.path.basename(file_path)
            try:
                if symbol_table.getPrimarySymbol(func.getEntryPoint()).getName().startswith("FUN_") or func.getName().startswith("FUN_"):
                    logger.warning(f"[+]FUNCTION FILTERED {project_name} -> {filename} -> {offset}: not start with FUN_")
                    continue
            except:
                logger.warning(f"[+]FUNCTION FILTERED {project_name} -> {filename} -> {offset}: not start with FUN_")
                continue
            try:
                decomp_result = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
                decompiled_function = decomp_result.getDecompiledFunction().getC()
                high_func = decomp_result.getHighFunction()
                update_func_by_decomp(high_func, program)
            except Exception as e:
                logger.error(f"[+]FUNCTION ERROR {project_name} -> {filename} -> {offset} :decompile failed {str(e)}")
                continue

            addrSet = func.getBody()
            codeUnits = listing.getCodeUnits(addrSet, True)

            assembly = []
            for codeUnit in codeUnits:
                instruction = codeUnit.toString()
                assembly.append(f"{filename}:[+0x{codeUnit.getMinAddress()}] {instruction}")

            args = get_args(high_func)
            signature = func.getSignature().getPrototypeString()
            ret = get_ret(high_func)

            func.getName()
            res[symbol_table.getPrimarySymbol(func.getEntryPoint()).getName()] = { **stripped_func, **{
                'demangled-name-dwarf': func.getName(),
                'assembly-dwarf': assembly,
                'pseudo-dwarf': decompiled_function,
                'args-dwarf': args,
                'signature-dwarf': signature,
                'ret-dwarf': ret,
            }}

            logger.info(f"[+]FUNCTION END {project_name} -> {filename} -> {offset}")

    return res




def adjust_so_name(origin_name: str, folder: str) -> str:
    """libnative-lib.so -> libnative-lib-dwarf.so"""
    if origin_name.find("-dwarf.so") != -1:
        return origin_name
    idx = origin_name.rindex(".")
    new_name = origin_name[:idx] + "-dwarf" + ".so"
    origin_path = os.path.join(folder, origin_name)
    new_path = os.path.join(folder, new_name)
    os.rename(origin_path, new_path)
    return new_name

def process(project_name: str, use_analysis_cache: bool):
    unstripped_folder = os.path.join(PROJECTS_FOLDER, project_name, "app-release-dwarf", "lib", "arm64-v8a")
    stripped_folder = os.path.join(PROJECTS_FOLDER, project_name, "app-release", "lib", "arm64-v8a")
    unstripped_files = [adjust_so_name(name, unstripped_folder) for name in sorted(os.listdir(unstripped_folder))]
    stripped_files = sorted(os.listdir(stripped_folder))
    if len(unstripped_files) != len(stripped_files):
        raise Exception(f"{project_name} has different so numbers in release-dwarf and release")
    if not use_analysis_cache:
        shutil.rmtree(f"{GHIDRA_PROJECT_FOLDER}/{project_name}")

    collected_folder = os.path.join(PROJECTS_FOLDER, project_name, 'collected')
    makedirs_if_necessary(collected_folder)

    for (unstripped_file, stripped_file) in zip(unstripped_files, stripped_files):
        logger.info(f"[+]FILE BEGIN {stripped_file}")
        stripped_info = process_stripped_so(os.path.join(stripped_folder, stripped_file), project_name)
        path = os.path.join(PROJECTS_FOLDER, project_name, 'debug', 'collected', f"{stripped_file}-stripped_info_debug.json")
        if not os.path.exists(os.path.dirname(path)):  #
            os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(stripped_info, f)

        collected = process_unstripped_so(stripped_info, os.path.join(unstripped_folder, unstripped_file), project_name)
        if len(collected) > 0:
            path = os.path.join(collected_folder, f"{unstripped_file}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(collected, f)
            logger.info(f"[+]FILE END {project_name} -> {stripped_file} : collected {unstripped_file}.json")
        else:
            logger.info(f"[+]FILE FILTERED {project_name} -> {unstripped_file} : collected is empty")



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
        process(project_name, True)
        logger.info(f"[+]PROJECT END {project_name}")
import argparse
import json
import logging
import os
from typing import List, Dict, Set

import pyghidra
pyghidra.start()
from ghidra.program.model.listing import Program, Function

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import ConsoleTaskMonitor
from utils.common_utils import get_logger, convert_dwarf_json_to_origin, makedirs_if_necessary

logger = get_logger("generate_call_relation.py", level=logging.INFO)
PROJECTS_FOLDER = os.getenv("PROJECTS_FOLDER", r"D:\Dataset")
GHIDRA_PROJECT_FOLDER = os.getenv("GHIDRA_PROJECT_FOLDER", r"D:\tmp\TempProject_CR")


def get_called_functions_with_callsite(flat_api: FlatProgramAPI, caller_function) -> Dict[str, Function]:
    """
    遍历 caller_function 内的所有调用指令，
    返回被调用函数对象集合（兼容 getCalledFunctions），
    并在每个函数对象上添加 callsite_offset 属性。
    """
    currentProgram = flat_api.getCurrentProgram()
    listing = currentProgram.getListing()
    instructions = listing.getInstructions(caller_function.getBody(), True)

    res = {}

    for instr in instructions:
        if instr.getFlowType().isCall(): # 只考虑调用指令
            call_addr = str(instr.getMinAddress())

            refs = instr.getReferencesFrom()
            for ref in refs:
                if ref.getReferenceType().isCall():
                    target_func = flat_api.getFunctionAt(ref.getToAddress())
                    if target_func:
                        res[call_addr] = target_func
                    else:
                        # 间接调用没有 Function 对象，这里跳过
                        pass
    return res

def get_call_relation_static(flat_api: FlatProgramAPI) -> Dict[str, Dict[str, Dict[str, Set[str]]]]:
    """
    分析当前程序，生成一个函数调用关系。

    返回:
        dict: 一个字典，键是调用者函数的起始偏移量(str)，
              值是一个dict: EXTERNAL -> 识别到的外部调用
                           INTERNAL -> 识别到的内部调用（注意，对于间接调用不会识别）
    """
    call_graph: Dict[str, Dict[str, Dict[str, Set[str]]]] = {}
    program = flat_api.getCurrentProgram()
    # 获取函数管理器，用于访问程序中的所有函数
    function_manager = program.getFunctionManager()
    monitor = ConsoleTaskMonitor()

    # 获取当前主程序的文件名，用于标识内部调用
    main_program_name = program.getName()

    print("正在分析 {} 个函数...".format(function_manager.getFunctionCount()))

    caller_function = flat_api.getFirstFunction()
    while caller_function is not None:
        # 只有在当前主程序中定义的函数才作为调用者进行分析
        if caller_function.getProgram().getName() != main_program_name:
            caller_function = flat_api.getFunctionAfter(caller_function)
            continue

        caller_offset = str(caller_function.getEntryPoint())
        # 为当前调用者函数初始化一个按库分类的被调用者字典
        callees_by_library: Dict[str, Dict[str, Set[str]]] = {}
        # 获取所有被调用的函数集合
        # called_functions = caller_function.getCalledFunctions(monitor)
        called_functions = get_called_functions_with_callsite(flat_api, caller_function)
        for callsite, callee_function in called_functions.items():
            callee_offset = str(callee_function.getEntryPoint())

            # note 不考虑外部调用的具体信息，我们只想要内部调用（且不是thunk，因为thunk函数一般没有意义），注意在极端情况下会有导致遗漏自定义的函数，而thunk实际的调用目标也会被动态分析抓取到，所以留在动态分析中
            if callee_function.isThunk() or callee_function.isExternal():
                library_name = "EXTERNAL"
            else:
                # library_name = main_program_name
                library_name = "INTERNAL"

            # 使用 setdefault 来优雅地处理新库名的情况（实际上目前只有两种情况：EXTERNAL和INTERNAL）
            # 如果 library_name 不在字典中，会先设置一个空字典 a.setdefault(key, {})
            # 然后再添加元素 xxx[callsite] = [callee_offset]，虽然只有1个元素，但是也要用List，因为将来动态信息会补充进去（对于静态调用、和非THUNK的，唯一
            callees_by_library.setdefault(library_name, {})[callsite] = {callee_offset}

        # 如果该函数有调用任何其他函数，则将其结果存入主调用图字典
        if callees_by_library:
            call_graph[caller_offset] = callees_by_library

        # next
        caller_function = flat_api.getFunctionAfter(caller_function)

    return call_graph


def get_call_relation_dynamic(flat_api: FlatProgramAPI, project_name: str, so_name: str, potential_func: Set[str]) -> Dict[str, Dict[str, Set[str]]]:
    """
    对于动态的信息，我们直接丢弃涉及thunk和external的call relation
    :return caller_offset -> {callee_offset, xxx}
    """
    dynamic_record_file_path = os.path.join(PROJECTS_FOLDER, project_name, "aligned_call", "dynamic_record", f"{so_name}.json")
    res: Dict[str, Dict[str, Set[str]]] = {} # res[caller] = {"callsite": [callee_offset], xxx} 因为一个调用点可能有多个calltarget（对于动态而言）
    # 如果不存在对应的文件，则直接返回
    if not os.path.exists(dynamic_record_file_path):
        logger.info("dynamic pass")
        return res

    # 将所有的calliste解析为function
    # 打开对应的so文件
    with open(dynamic_record_file_path, 'r', encoding='utf-8') as f:
        dynamic_record: List[List[str]] = json.load(f) # 它是一个List[List[str]]
        for callstack in dynamic_record:
            # callstack是一个采样点对应的调用栈，但是其对应的偏移地址实际上是callsite的偏移地址，而且不满足规范
            try:
                # 规范化后的callsites = [c_1, c_2, ..., c_n]
                callsites = [str(flat_api.toAddr(offset)) for offset in callstack]
                # fixed_callstack = [f_1, f_2, ..., f_n]
                fixed_callstack = [str(flat_api.getFunctionContaining(flat_api.toAddr(offset)).getEntryPoint()) for offset in callstack]
                # 而且是按照从栈底到栈顶的方式排列的，v[0]是栈底，c_1 of f_1 call f_2
                for callsite, caller, callee in zip(callsites, fixed_callstack, fixed_callstack[1:]):
                    # 如果caller和callee是thunk或external，跳过
                    caller_func = flat_api.getFunctionAt(flat_api.toAddr(caller))
                    callee_func = flat_api.getFunctionAt(flat_api.toAddr(callee))
                    potential_func.add(str(caller_func.getEntryPoint()))
                    potential_func.add(str(callee_func.getEntryPoint()))
                    if caller_func.isThunk() or caller_func.isExternal() or callee_func.isThunk() or callee_func.isExternal():
                        continue
                    # 将caller和callee组成一对，放到caller指示的集合中
                    # res.setdefault(caller, set()).add(callee)
                    res.setdefault(caller, {}).setdefault(callsite, set()).add(callee) # 由集合（只包含callee）更改为包含callsite的entry
            except:
                # 抛出异常则跳过当前的栈帧处理
                continue

    return res


def generate_call_relation(project_name: str):
    # 考虑只处理需要处理的so文件，即generate_ground_truth文件夹下的so文件（也就是aligned_extract文件夹下的文件，为了并行性，应当选择后者）
    align_extract_folder = os.path.join(PROJECTS_FOLDER, project_name, "aligned_extract")
    so_names = [convert_dwarf_json_to_origin(name) for name in os.listdir(align_extract_folder) if not name.startswith(".")] # 别忘了转换名称

    call_relation_folder = os.path.join(PROJECTS_FOLDER, project_name, "call_relation")
    potential_func_folder = os.path.join(PROJECTS_FOLDER, project_name, "potential_func")
    makedirs_if_necessary(call_relation_folder)
    makedirs_if_necessary(potential_func_folder)

    for so_name in so_names:
        call_relation_path = os.path.join(call_relation_folder, f"{so_name}.json")
        potential_func_path = os.path.join(potential_func_folder, f"{so_name}.json")
        potential_func = set()
        res = {}
        if os.path.exists(call_relation_path):
            with open(call_relation_path, 'r', encoding='utf-8') as f:
                res = json.load(f)

        stripped_file_path = os.path.join(PROJECTS_FOLDER, project_name, "app-release", "lib", "arm64-v8a", so_name)
        logger.info(f"======process {so_name}")
        # 这里加上“-2”后缀是为了能够与align pseudo并行执行
        with pyghidra.open_program(stripped_file_path, project_location=GHIDRA_PROJECT_FOLDER, project_name=project_name, analyze=True) as flat_api:
            # init
            program = flat_api.getCurrentProgram()
            # 设置默认的起始地址为0
            new_base_addr = flat_api.toAddr(0x0)
            program.setImageBase(new_base_addr, True)

            # 如果之前已经有了结果，那么将跳过静态分析，编译累计动态分析的结果
            if not res:
                # 生成静态分析结果
                static_call_relation = get_call_relation_static(flat_api)
                res = static_call_relation
            # 解析动态分析结果
            dynamic_call_relation = get_call_relation_dynamic(flat_api, project_name, so_name, potential_func)
            # 汇总
            # 由于动态分析只考虑内部调用，所以这里只需要修改INTERNAL的内容，由于是集合，可以直接取并集
            for caller, callee_map in dynamic_call_relation.items():
                # 将callee_map合并到static的caller指示的内容中
                # static_call_relation.setdefault(caller, {"INTERNAL": set()}).setdefault("INTERNAL", set()).update(callee_set)
                res_map = res.setdefault(caller, {"INTERNAL": {}}).setdefault("INTERNAL", {})
                # 处理callee_map
                for callsite, calltarget_set in callee_map.items():
                    if callsite in res_map:
                        res_map[callsite] = set(res_map[callsite])
                    else:
                        res_map[callsite] = set()
                    res_map[callsite].update(calltarget_set)

            # 由于set不可序列化，需要将其转化为list
            for caller, values in res.items():
                for key in values:
                    for callsite, info  in values[key].items():
                        values[key][callsite] = list(values[key][callsite]) # 这里需要强制将其转化为list

            # save
            with open(call_relation_path, 'w', encoding='utf-8') as f:
                json.dump(res, f)
            with open(potential_func_path, 'w', encoding='utf-8') as f:
                json.dump(list(potential_func), f)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--project_names', nargs='+', help='project_names?')
    args = parser.parse_args()
    project_names = args.project_names

    if len(project_names) == 0:
        # 如果用户没有传入参数，则分析目录下的每个项目
        project_names = [name for name in os.listdir(PROJECTS_FOLDER) if not name.startswith(".")]
    # 否则按照指定的项目区目录下找
    print(project_names)
    for project_name in project_names:
        logger.info(f"[+]PROJECT BEGIN {project_name}")
        generate_call_relation(project_name)
        logger.info(f"[+]PROJECT END {project_name}")
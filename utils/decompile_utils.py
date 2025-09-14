from typing import List, Dict, Any
import pyghidra
pyghidra.start()


from ghidra.program.model.listing import ParameterImpl, ReturnParameterImpl, Function, Program
from ghidra.program.model.pcode import HighFunction
from ghidra.program.model.symbol import SourceType


def update_func_by_decomp(high_func: HighFunction, program: Program):
    # note 可以通过如下的方式直接得到反编译分析的函数的参数和返回值分析结果（通过getStorage可以获得存储位置，可用于汇编代码）
    proto = high_func.getFunctionPrototype()
    return_type = proto.getReturnType()
    return_storage = proto.getReturnStorage() # 这也是关键（包括params部分的getStorage()，通过次可以实现让反编译的结果更新汇编内容，特别是栈变量/寄存器变量等）
    param_count = proto.getNumParams()
    # 参数
    params = [ParameterImpl(proto.getParam(i).getName(), proto.getParam(i).getDataType(), proto.getParam(i).getStorage(), program) for i in range(param_count)]

    # 返回变量
    return_var =  ReturnParameterImpl(return_type, return_storage, True, program)

    high_func.getFunction().updateFunction(
        high_func.getFunctionPrototype().getModelName(),
        return_var,
        Function.FunctionUpdateType.CUSTOM_STORAGE,
        True,
        SourceType.USER_DEFINED,
        params,
    )

def get_args(hf : HighFunction) -> List[Dict[str, Any]]:
    """
    :param hf:
    :return: list of every arg info: organized as follows:
    {
        name: arg_name,
        type: arg_type,
        storage: register names or stack offsets
    }
    """
    func = hf.getFunction()
    # proto = hf.getFunctionPrototype()
    # param_count = proto.getNumParams()
    param_count = func.getParameterCount()
    params = []
    for i in range(param_count):
        param = {
            'name': func.getParameter(i).getName(),
            'type': func.getParameter(i).getDataType().getDisplayName()
        }
        p = func.getParameter(i)
        if p.isRegisterVariable():
            param['storage'] = [reg.getName() for reg in list(p.getRegisters())] # note 收集所有可能的候选寄存器的名称（但是它们的长度应该一致）
            if p.hasStackStorage(): # 如果同时存储在了栈中，说明它是一个复合类型的存储，也应该把栈偏移添加到其中
                param['storage'].append(hex(p.getStackOffset())) # 将其转化为16进制的字符串
        elif p.hasStackStorage(): # 这个条件是判断是否**仅**在栈中存储
            param['storage'] = [p.getStackOffset()]
        else:
            param['storage'] = [] # 用空列表表示没有识别到

        param['width'] = int(p.getLength()) # 存储宽度

        params.append(param)
    # for i in range(param_count):
    #     param = {
    #         "name": proto.getParam(i).getName(),
    #         "type": proto.getParam(i).getDataType().getDisplayName()
    #     }
    #     storage = proto.getParam(i).getStorage()
    #     if storage.isRegisterStorage():
    #         param['storage'] = [(reg.getName()) for reg in list(storage.getRegisters())] # 收集所有可能的候选寄存器的名称
    #         if storage.hasStackStorage(): # 如果同时存储在了栈中，说明它是一个复合类型的存储，也应该把栈偏移添加到其中
    #             param['storage'].push(hex(storage.getStackOffset())) # 将其转化为16进制的字符串
    #     elif storage.isStackStorage(): # 这个条件是判断是否**仅**在栈中存储
    #         param['storage'] = [storage.getStackOffset()]
    #     else:
    #         param['storage'] = [] # 用空列表表示没有识别到
    #
    #     params.append(param)

    return params


def get_ret(hf: HighFunction) -> Dict[str, Any]:
    # 获取返回值位置
    # proto = func.getFunctionPrototype()
    func = hf.getFunction()
    ret_type = func.getReturnType().getDisplayName() # 类型的名称
    r = func.getReturn()
    if r.isRegisterVariable():
        ret_loc = [reg.getName() for reg in r.getRegisters()] # 一个列表，长度都一样
        if r.hasStackStorage(): # 如果同时存储在栈中，则将对应的栈偏移加上
            ret_loc.append(hex(r.getStackOffset()))
    elif r.isStackVariable():
        ret_loc = [r.getStackOffset()]
    else:
        ret_loc = [] # 用空列表表示没有识别到
    return {
        'type': ret_type,
        'storage': ret_loc,
        'width': int(r.getLength())
    }
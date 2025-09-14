import logging
import os.path


def get_logger(file_name: str, mode: str = 'w', level: int = logging.WARNING) -> logging.Logger:
    # 创建Logger
    logger = logging.getLogger(file_name)
    logger.setLevel(level)  # 设置日志级别
    # 创建文件Handler，用于写入日志文件
    file_handler = logging.FileHandler(os.path.join(file_name+'.log'), mode=mode)
    file_handler.setLevel(logging.DEBUG)
    # 创建控制台Handler，用于输出到控制台
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def makedirs_if_necessary(dir_path: str):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)

def convert_dwarf_json_to_origin(gt_filename: str) -> str:
    # gt_filename = libxxx-dwarf.so.json，也即后14个字符都是不需要的，去掉，并在后面添加so
    return gt_filename[:-14] + ".so"

def convert_origin_to_dwarf_json(so_name: str) -> str:
    # so_name = libxxx.so => libxxx-dwarf.so.json
    return so_name[:-3] + "-dwarf.so.json"
import sqlite3
import threading
import json
import os
from typing import Dict, Optional, List


class PersistentCache:
    def __init__(self, db_name: str = "cache.db", table_name: str = "cache", folder: str = "", use_history: bool = True):
        """
        :param db_name: 数据库文件名（不包含路径）
        :param table_name: 表名
        """
        # 构造数据库路径：当前文件所在目录/db/folder/数据库文件
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_dir = os.path.join(base_dir, "db", folder)
        os.makedirs(db_dir, exist_ok=True)  # 自动创建 db 文件夹
        self.db_path = os.path.join(db_dir, db_name)

        self.cache: Dict[str, Dict[str, str]] = {}  # 内存缓存
        self.lock = threading.Lock()
        self.table_name = table_name
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._create_table()
        self._load_cache()
        if not use_history:
            self.clear()

    def _create_table(self):
        """创建数据库表"""
        with self.conn:
            self.conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.table_name} (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

    def _load_cache(self):
        """启动时加载数据库内容到内存"""
        cursor = self.conn.execute(f"SELECT key, value FROM {self.table_name}")
        for key, value_json in cursor.fetchall():
            try:
                self.cache[key] = json.loads(value_json)
            except json.JSONDecodeError:
                self.cache[key] = {}

    def set(self, key: str, value: Dict[str, str | Dict]):
        """添加或更新缓存（持久化到数据库）"""
        with self.lock:
            self.cache[key] = value
            with self.conn:
                self.conn.execute(
                    f"INSERT OR REPLACE INTO {self.table_name} (key, value) VALUES (?, ?)",
                    (key, json.dumps(value, ensure_ascii=False))
                )

    def get(self, key: str) -> Optional[Dict[str, str | Dict]]:
        """查询缓存"""
        return self.cache.get(key)

    def has_key(self, key: str) -> bool:
        """检测目标 key 是否在缓存中"""
        return key in self.cache

    def delete(self, key: str):
        """删除缓存"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
            with self.conn:
                self.conn.execute(f"DELETE FROM {self.table_name} WHERE key=?", (key,))

    def clear(self):
        """清空缓存"""
        with self.lock:
            self.cache.clear()
            with self.conn:
                self.conn.execute(f"DELETE FROM {self.table_name}")

    def export_to_json(self, file_path: str):
        """将当前 cache 序列化到指定路径形成 JSON 文件"""
        with self.lock:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)

    def import_from_json(self, file_path: str):
        """
        从 JSON 文件导入缓存，并同步更新到 SQLite 数据库
        - 会清空当前缓存和数据库内容
        - 将 JSON 文件内容写入缓存和数据库
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")

        with self.lock:
            with open(file_path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                    if not isinstance(data, dict):
                        raise ValueError("JSON 文件格式错误：根元素必须是字典")
                except json.JSONDecodeError:
                    raise ValueError("JSON 文件解析失败")

            # 清空内存缓存和数据库
            self.cache.clear()
            with self.conn:
                self.conn.execute(f"DELETE FROM {self.table_name}")

                # 导入数据
                for key, value in data.items():
                    if not isinstance(value, dict):
                        raise ValueError(f"键 {key} 的值不是字典")
                    self.cache[key] = value
                    self.conn.execute(
                        f"INSERT OR REPLACE INTO {self.table_name} (key, value) VALUES (?, ?)",
                        (key, json.dumps(value, ensure_ascii=False))
                    )

    def close(self):
        """关闭数据库连接"""
        self.conn.close()


# # 测试代码
# if __name__ == "__main__":
#     cache = PersistentCache(db_name="my_cache.db", table_name="my_table")
#
#     cache.set("user:1", {"name": "Alice", "email": "alice@example.com"})
#     cache.set("user:2", {"name": "Bob", "email": "bob@example.com"})
#
#     print("当前缓存:", cache.cache)
#
#     # 导出
#     cache.export_to_json("cache_export.json")
#
#     # 清空并导入
#     cache.clear()
#     print("清空后:", cache.cache)
#
#     cache.import_from_json("cache_export.json")
#     print("导入后:", cache.cache)
#
#     cache.close()

import time

class Timer:
    def __init__(self):
        self.start_time = None
        self.pause_time = None
        self.total_paused_time = 0
        self.running = False
        self.paused = False
        self.pause_count = 0  # 暂停次数
        self.actual_time = None
        self.effective_time = None

    def start(self):
        """开始计时"""
        if not self.running:
            self.start_time = time.time()
            self.running = True
            self.total_paused_time = 0
            self.paused = False
            self.pause_count = 0
            print("计时器已开始")
        # else:
        #     print("计时器已经在运行中")

    def pause(self):
        """暂停计时"""
        if self.running and not self.paused:
            self.pause_time = time.time()
            self.paused = True
            self.pause_count += 1
            # print(f"计时器已暂停（第 {self.pause_count} 次）")
        # elif self.paused:
        #     print("计时器已经暂停中")
        # else:
        #     print("计时器还未开始")

    def resume(self):
        """恢复计时"""
        if self.running and self.paused:
            paused_duration = time.time() - self.pause_time
            self.total_paused_time += paused_duration
            self.paused = False
            # print("计时器已恢复")
        # elif not self.paused:
        #     print("计时器当前未暂停")
        # else:
        #     print("计时器还未开始")

    def stop(self):
        """停止计时并返回时间统计"""
        if self.running:
            if self.paused:
                end_time = self.pause_time
            else:
                end_time = time.time()

            # 实际经过时间（包含暂停）
            self.actual_time = end_time - self.start_time
            # 有效运行时间（排除暂停）
            self.effective_time = self.actual_time - self.total_paused_time

            self.running = False
            self.paused = False
            print(f"计时器已停止")
            print(f"实际经过时间: {self.actual_time:.2f} 秒")
            print(f"有效运行时间: {self.effective_time:.2f} 秒")
            print(f"总暂停次数: {self.pause_count} 次")
            # return self.actual_time, self.effective_time, self.pause_count
        else:
            print("计时器还未开始")
            # return 0, 0, 0

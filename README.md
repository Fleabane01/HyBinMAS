# Towards Robust Function Name Recovery in Stripped Binaries: A Multi-Agent Framework with Hybrid Analysis
This repository contains the code implementation of paper "Towards Robust Function Name Recovery in Stripped Binaries: A Multi-Agent Framework with Hybrid Analysis".

We implemented HyBinMAS using [Ghidra](https://ghidra-sre.org/) (for decompilation), [tree-sitter](https://tree-sitter.github.io/tree-sitter/) (for processing source code and decompiled code).



##  Dataset
The original binaries (Release and Release-DWARF) used by HyBinMAS can be downloaded [here](https://drive.google.com/file/d/1MtyYN4YUWsd_BXGrbfYCDS211IqUpK7R/view?usp=sharing) or [here](https://zenodo.org/records/17116383?token=eyJhbGciOiJIUzUxMiJ9.eyJpZCI6IjllOWE3MDAzLWNiNWItNGU3NS1hYWY1LWNjMGE0ZWJiOTA4NiIsImRhdGEiOnt9LCJyYW5kb20iOiI3ZjRjN2NlN2ViZjk0NDFiN2U5OWM5MjgyMDhlNjk4OCJ9.fpMD9sXwGQsD6utlIi7SmtjtHWuJ-GB9ksG-zW0uTbrFmXSXnAg70QVWjH2Fzj64taLiJ3KoX4goy8cARKJ7iA).

## Setup
1. use requirements.txt to install env
2. download frida17.2.0(client and server), and send server to `/data/local/tmp/frida17.2.0` of target Android device
3. download simpleperf and send it to `/data/local/tmp/simpleperf`

## Running Steps

### Construct Dataset
The first step is to obtain the Dataset.
The related scripts are in the folder [`consturct-dataset`](consturct-dataset).

Specify the corresponding path noted by `TODO`

1. run `collect_and_align2dwarf.py`
   ```bash
   python construct-dataset/collect_and_align2dwarf.py --project_names PROJECT_NAMES
   ```
2. run `align_dwarf_with_source.py`
   ```bash
   python construct-dataset/align_dwarf_with_source.py --project_names PROJECT_NAMES
   ```
3. run `extract_soufce_function.py`
   ```bash
   python construct-dataset/extract_soufce_function.py --project_names PROJECT_NAMES
   ```
4. run simpleperf to capture callstack
   1. run simpleperf
      ```bash
      adb shell "/data/local/tmp/simpleperf record -p <PID> -g --duration 10 -o /data/local/tmp/perf.data"
      ```
   2. process perf data
      ```bash
      adb shell "/data/local/tmp/simpleperf report -g /data/local/tmp/perf.data > /data/local/tmp/callstack.txt"
      ```
   3. pull callstack.txt to local machine, save to `SIMPLEPERF_DATA_FOLDER/<project_name>/callstack`
5. run `analysis_simpleperf_callstack.py`
   ```bash
   python construct-dataset/analysis_simpleperf_callstack.py --project_names PROJECT_NAMES
   ```
6. run `generate_call_relation.py`
   ```bash
   python construct-dataset/generate_call_relation.py --project_names PROJECT_NAMES
   ```


### Predict
1. run static partition of SR:
   ```bash
   python main.py --p xxx --f xxx --use_call_relation
   ```
2. run test_generator.py
   ```bash
   python test_generator.py --project_names xxx --mode orchestrator
   # python test_generator.py --project_names xxx --mode materializer
   ```
3. run executor
   ```bash
   python executor_prelude.py --p xxx --f xxx
   python executor.py --p xxx --f xxx
   python executor_epilogue.py --p xxx --f xxx
   ```
4. run execution_validator.py
   ```bash
   python execution_validator.py --p xxx --f xxx --iter xxx
   ```
5. run dynamic partition of SR:
   ```bash
   python main.py --p xxx --f xxx --use_call_relation --use_dynamic_info
   ```


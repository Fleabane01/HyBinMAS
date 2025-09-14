function bytesToHex(buffer: ArrayBuffer | null): string {
    if (!buffer) return "";
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');
}

function setRegs(regs: any, context: CpuContext) {
    for (const [k, v] of Object.entries(JSON.parse(JSON.stringify(context))) ) {
        if("pc" === k){
            continue;
        }
        if(k.startsWith("q")){
            continue;
        }
        let vStr = formatRegValue(v);
        if("nzcv" === k) {
            vStr = parseNZCV(vStr);
        }
        regs[k] = vStr;
    }
}

function formatRegValue(val: any): string {
    if(!val) {
        return "0";
    }
    if(typeof val === 'string') {
        return val;
    }

    if(typeof val === 'number') {
        return val.toString();
    }

    return JSON.stringify(val);
}

function parseNZCV(nzcvStr: string): string {
    try {
        const nzcvValue = Number.parseInt(nzcvStr);

        const N = (nzcvValue >>> 31) & 1;
        const Z = (nzcvValue >>> 30) & 1;
        const C = (nzcvValue >>> 29) & 1;
        const V = (nzcvValue >>> 28) & 1;

        return `N=${N};Z=${Z};C=${C};V=${V}`;
    } catch (e) {
        return nzcvStr;
    }
}

function getChangedRegs(
    lastRegs: any,
    context: CpuContext
  ): [string, any, any][] {
    let changed : [string, any, any][] = [];
    const curRegs: [string, any][]= Object.entries(JSON.parse(JSON.stringify(context)));
    for(const [k, v] of curRegs){
        if(k.startsWith("q")){
            continue;
        }
        let vStr = formatRegValue(v);
        let lastStr = formatRegValue(lastRegs[k]);
        if("nzcv" === k) {
            vStr = parseNZCV(vStr);
            lastStr = parseNZCV(lastStr);
        }
        if("pc" !== k && vStr != lastStr) {
            changed.push([k, lastStr, vStr]);
        }
        lastRegs[k] = v;
    }
    return changed;
}


let id = 0;
function hook_specified_function_with_stalker(name: string, idx: string, beginOffset: number, endOffset: number, writeArgsBody: string, readArgsBody: string, readRetBody: string) {
    console.log(`beginOffset = ${beginOffset}, endOffset =${endOffset}`);
    const module = Process.getModuleByName(name);
    if(module == null){
        console.error("couldn't find module")
    }
    const baseAddr = module.base;
    const beginAddr = module.base.add(beginOffset);
    const endAddr = module.base.add(endOffset);
    // 获取目标函数的ptr
    const fnPtr = baseAddr.add(beginOffset);
    if(!fnPtr){
        console.error("couldn't find function addr");
        return;
    }
    console.log("target function:", fnPtr);
    let isTraced: boolean = false;
    let buffer: string[] = [];
    try {
        const readArgs = eval(`(ctx) => { ${readArgsBody} }`);
        const writeArgs = eval(`(ctx) => { ${writeArgsBody} }`);
        const readRet = eval(`(ctx) => { ${readRetBody} }`);
        console.log("created");
            // 拦截
        Interceptor.attach(fnPtr, {
            onEnter: function(args) {
                if(isTraced){
                    return;
                }
                this.tid = Process.getCurrentThreadId();

                const ctx = this.context as Arm64CpuContext;
                try {
                    writeArgs(ctx);
                } catch (e: any) {
                    console.log(`[writeArgs runtime error], beginOffset = ${beginOffset} ${e.message}`)
                    send({
                        type: "writeArgs-error",
                        idx: idx,
                        offset: beginOffset,
                        content: e.message + '\n' + e.stack
                    });
                }

                id++;
                let lastRegs = {};
                console.log(`hooked beginOffset = ${beginOffset}, endOffset =${endOffset}`);
                setRegs(lastRegs, this.context);
                buffer.push(
                    `all regs value at function entry point: ${JSON.stringify(lastRegs)}`
                );
                Stalker.follow(this.tid, {
                    events: {
                        call: false,
                        ret: false,
                        exec: true,
                        block: true,
                        compile: false
                    },
                    transform(iterator: StalkerArm64Iterator) {
                        let instruction;
                        let count = 1;
                        while((instruction = iterator.next()) !== null) {
                            iterator.keep();
                            if(instruction.address.compare(beginAddr) >= 0 && instruction.address.compare(endAddr) <= 0) {
                                iterator.putCallout(function (context) {
                                    const localInstr = Instruction.parse(context.pc);
                                    const localAddr = localInstr.address;
                                    const instructionOffset = localAddr.sub(baseAddr);
                                    const changedRegs = JSON.stringify(getChangedRegs(lastRegs, context));
                                    buffer.push(
                                        `[${instructionOffset}] ${localInstr.mnemonic} ${localInstr.opStr} | ${changedRegs}`
                                    );
                                });
                            }
                        }
                    },
                });
            }, 
            onLeave(retval) {
                if(isTraced){
                    return;
                }
                isTraced = true;
                let lastRegs = {};
                setRegs(lastRegs, this.context);
                Stalker.unfollow(this.tid);
                buffer.push(
                    `context info at function return: ${JSON.stringify(lastRegs)}`
                );

                const ctx = this.context as Arm64CpuContext;
                let actualArgsInfo;
                try {
                    actualArgsInfo = readArgs(ctx);

                    send({
                        type: "args",
                        idx: idx,
                        offset: beginOffset,
                        content: actualArgsInfo
                    });
                } catch (e: any) {
                    console.log(`[readArgs runtime error], beginOffset = ${beginOffset} ${e.message}`)
                    send({
                        type: "readArgs-error",
                        idx: idx,
                        offset: beginOffset,
                        content: e.message + '\n' + e.stack
                    });
                }
                
                let actualRetInfo;
                try {
                    actualRetInfo = readRet(ctx);

                    send({
                        type: "ret",
                        idx: idx,
                        offset: beginOffset,
                        content: actualRetInfo
                    });
                } catch (e: any) {
                    console.log(`[readRet runtime error], beginOffset = ${beginOffset} ${e.message}`)
                    send({
                        type: "readRet-error",
                        idx: idx,
                        offset: beginOffset,
                        content: e.message + '\n' + e.stack
                    });
                }
                send({
                    type: "trace",
                    idx: idx,
                    offset: beginOffset,
                    content: buffer
                });
            }
        });
    } catch (err: any) {
        send({
            type: "func-create-error",
            idx: idx,
            offset: beginOffset,
            content: err.message + '\n' + err.stack
        });
        return;
    }
}



export {
    hook_specified_function_with_stalker,
}
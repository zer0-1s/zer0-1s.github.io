---
updateTime: "2025-04-10 10:58"
desc: "ehids代码解读"
tags: "HIDS/源码分析"
outline: deep
---
# eHIDS代码解析1

## 1. 包声明

```go
package user ("ehids/user")
```

这里声明了 `user` 包，并指定了它的导入路径为 `"ehids/user"`。这意味着这个包的代码位于项目目录结构中的 `ehids/user` 文件夹下。

## 2. 函数定义

```go
func user.GetModules() map[string]user.IModule  // map[key]value
```

`user.GetModules()` 是一个函数，它返回一个类型为 `map[string]user.IModule` 的值。

- 映射的键是 `string` 类型，表示模块的名称。
- 映射的值是 `user.IModule` 类型，表示模块对象，这些模块对象实现了 `user.IModule` 接口。

### `user.IModule` 接口

在之前的代码中，`user.IModule` 接口定义如下：

```go
type IModule interface {
    // Init 初始化
    Init(context.Context, *log.Logger) error

    // Name 获取当前module的名字
    Name() string

    // Run 事件监听感知
    Run() error

    // Start 启动模块
    Start() error

    // Stop 停止模块
    Stop() error

    // Close 关闭退出
    Close() error

    SetChild(module IModule)

    Decode(*ebpf.Map, []byte) (string, error)

    Events() []*ebpf.Map

    DecodeFun(p *ebpf.Map) (IEventStruct, bool)
}
```

这个接口定义了模块的基本行为，包括初始化、启动、停止、事件解码等方法。

### `user.GetModules()` 的作用

`user.GetModules()` 的作用是返回一个包含所有已注册模块的映射。这些模块通常在程序启动时通过 `user.Register` 函数注册到全局模块表中。例如：

```go
var modules = make(map[string]IModule)

func Register(p IModule) {
    if p == nil {
        panic("Register probe is nil")
    }
    name := p.Name()
    if _, dup := modules[name]; dup {
        panic(fmt.Sprintf("Register called twice for probe %s", name))
    }
    modules[name] = p
}

func GetModules() map[string]IModule {
    return modules
}
```

- `Register` 函数用于将模块注册到全局模块表 `modules` 中。
- `GetModules` 函数返回这个全局模块表的副本。

### 使用 `user.GetModules()`

在主程序中，你可以通过调用 `user.GetModules()` 来获取所有已注册的模块，并对它们进行操作。例如：

```go
modules := user.GetModules()
for name, module := range modules {
    fmt.Printf("Module name: %s\n", name)
    err := module.Init(context.Background(), log.Default())
    if err != nil {
        fmt.Printf("Failed to initialize module %s: %v\n", name, err)
        continue
    }
    go func(m user.IModule) {
        err := m.Run()
        if err != nil {
            fmt.Printf("Error running module %s: %v\n", m.Name(), err)
        }
    }(module)
}
```

- 获取所有模块。
- 遍历模块，初始化并启动每个模块。

`user.GetModules()` 是一个非常重要的函数，它提供了一个集中管理模块的方式。通过这个函数，你可以轻松地获取所有已注册的模块，并对它们进行初始化、启动、停止等操作。这种模块化的设计使得代码更加清晰、易于维护，并且便于扩展。

---

## 示例代码

```go
package main

import (
    ...
)

func main() {
    ctx, cancelFun := context.WithCancel(context.TODO())

    ...

    // 加载ebpf，挂载到hook点上，开始监听
    go func(module user.IModule) { 
        err := module.Run() // 内含 Done() 通道
        if err != nil {
            logger.Printf("%v\n", err)
        }
    }(module)

    <-stopper
    cancelFun()

    logger.Println("Received signal, exiting program..")
    time.Sleep(time.Millisecond * 100)
}
```

`context.WithCancel` 和 `cancelFun` 提供了一种优雅的方式来管理和取消并发任务。通过监听上下文的 `Done()` 通道，goroutine 可以在上下文被取消时停止工作，从而实现优雅的关闭。

---

## 审计 `copy_process` 参数的原因

创建新的 namespace 是非常重要的一步。

### 代码解读

#### `proc_kern.c`

每种 hook 点的内核态文件之前定义本 hook 点对应的结构体：

```c
SEC("kretprobe/copy_process") // 重要 key point
```

```c
#include "ehids_agent.h"

#define MAX_DEPTH 10

#define ENABLE_FORK
#define ENABLE_EXEC
#define ENABLE_EXIT

typedef enum my_event_type_t {
    EVENT_FORK = 1,
    EVENT_EXEC = 2,
    EVENT_EXIT = 3
} my_event_type;

typedef struct _process_info_t {
    int type;
    pid_t child_pid;
    pid_t child_tgid;
    pid_t parent_pid;
    pid_t parent_tgid;
    pid_t grandparent_pid;
    pid_t grandparent_tgid;
    uid_t uid;
    gid_t gid;
    int cwd_level;
    u32 uts_inum;
    __u64 start_time;
    char comm[16];
    char cmdline[128];
    char filepath[128];
} proc_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // need page align
} ringbuf_proc SEC(".maps");

SEC("kretprobe/copy_process")
int kretprobe_copy_process(struct pt_regs *regs) {
#ifdef ENABLE_FORK
    struct task_struct *task = (struct task_struct *)PT_REGS_RC(regs);  // copy_process 返回的是子进程 task_struct
    proc_info_t *ringbuf_process;

    ringbuf_process = bpf_ringbuf_reserve(&ringbuf_proc, sizeof(proc_info_t), 0);
    if (!ringbuf_process)
        return -1;

    ringbuf_process->type = EVENT_FORK;
    ringbuf_process->child_pid = BPF_CORE_READ(task, pid);
    ringbuf_process->child_tgid = BPF_CORE_READ(task, tgid);
    bpf_get_current_comm(ringbuf_process->comm, 16);
    bpf_ringbuf_submit(ringbuf_process, 0);
#endif
    return 0;
}
```

目前这里的设计是内核 hook 点的进程信息都存在 ringbuf 缓冲区，所以缓冲区满的时候数据会出现覆盖，新数据覆盖旧数据。

---

## `ForkProcEvent` 结构体

围绕 `ForkProcEvent` 结构体，实现了从二进制数据解析、转换为字符串表示、克隆实例以及构建 CWD 路径等功能，主要用于处理和操作与进程 fork 事件相关的数据。

---

## 为什么选择内核模块 `.ko`

| 维度               | eBPF                  | LKM (.ko)            |
|--------------------|-----------------------|----------------------|
| 安全限制           | 严格                 | 自由                 |
| 可访问结构         | 受限于 verifier      | 完整访问             |
| 检测逻辑复杂度     | 适合轻量事件         | 适合复杂逻辑         |
| 可执行操作         | 只能观察             | 可以干预             |
| 适用场景           | 实时监控 / 日志      | 行为检测 / 拦截 / 攻防 |

---

## 混合使用 eBPF 和 LKM

现在也有不少项目用 eBPF + LKM 混合的方式：

- **eBPF**：负责快速采集事件。
- **LKM 或 userspace**：负责重构上下文 + 深度检测。

例如：

- Cilium（网络层）
- Tracee（容器行为审计）
- Falco（行为监控）

package sandbox

import "fmt"

// Level 隔离档位。
//
// 序即强弱：Level 越大，被执行的程序能触达的东西越少。
//
// # 零值是最弱的一档，这是刻意的
//
// 未声明档位的 Provider 零值即 LevelNone，于是它只会被「要求=none」选中，
// 而任何更高要求的执行都会因「无满足者」而**拒绝执行**。方向是安全的那一侧：
// 漏声明的后端拿到的是最弱的选择，不是最强的豁免。
type Level uint8

const (
	// LevelNone 无隔离：被执行的程序与宿主同权限，能触达宿主能触达的一切。
	//
	// 它是**显式的一档**，不是「缺省即无」：把「没有隔离」写成档位，宿主就必须
	// 显式登记一个这样的后端，而不是让「没登记」悄悄等于「没隔离」。
	LevelNone Level = iota

	// LevelProcess 进程内解释器边界：程序跑在宿主进程内的解释器里，能力面靠
	// 语言子集 + 显式绑定白名单裁剪，资源面靠预算裁剪。
	//
	// 它**不是**内核级边界：这层约束由解释器自己执行，解释器自身的缺陷可以
	// 越过它。故把它标成 LevelOS 就是让档位表说谎，而档位表是宿主做风险判断的
	// 依据——说谎的成本落在宿主身上。
	LevelProcess

	// LevelOS 内核级边界：文件、网络、系统调用由内核策略裁剪。
	LevelOS

	// LevelMachine 硬件虚拟化边界：被执行的程序有自己的内核与虚拟设备。
	LevelMachine
)

// levelNames 档位名，与 String 一致；下标即档位序。
var levelNames = [...]string{"none", "process", "os", "machine"}

// String 档位名。
func (l Level) String() string {
	if int(l) < len(levelNames) {
		return levelNames[l]
	}
	return fmt.Sprintf("level(%d)", uint8(l))
}

// ParseLevel 解析档位名。未知档位即报错，不退回某个缺省档位。
//
// 为什么不给缺省：档位名多半来自宿主自己的配置。配置写错时静默退回
// LevelNone，等于把「我以为很强」变成「其实没有」——而这正是本包要防的那类
// 落差。响亮失败比安静降级好。
func ParseLevel(s string) (Level, error) {
	for i, n := range levelNames {
		if n == s {
			return Level(i), nil
		}
	}
	return LevelNone, fmt.Errorf("sandbox: 未知隔离档位 %q（可选：none/process/os/machine）", s)
}

// AtLeast 报告 l 是否达到（或超过）min。
func (l Level) AtLeast(min Level) bool { return l >= min }

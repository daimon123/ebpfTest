package main

import (
	"bytes"
	"context"
	"fmt"
	ebpfspy "github.com/grafana/pyroscope/ebpf"
	"github.com/grafana/pyroscope/ebpf/metrics"
	"github.com/grafana/pyroscope/ebpf/symtab"
	"github.com/grafana/pyroscope/ebpf/symtab/elf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netns"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/coroot/coroot-node-agent/containers"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/coroot-node-agent/profiling"
	"github.com/go-kit/log"
	"golang.org/x/sys/unix"
)

type Config struct {
	Database struct {
		Host     string
		Port     int
		User     string
		Password string
		Name     string
	}
	Server struct {
		Port int
	}
}

type Manager struct {
	cfgFile string
	config  Config

	cgroup *Cgroup

	// Namespace
	selfNetNs   netns.NsHandle
	hostNetNs   netns.NsHandle
	hostNetNsId string

	hostname   string
	systemUUID string
	machineId  string

	agentPid          uint32
	containerIdRegexp *regexp.Regexp

	processInfoCh chan<- containers.ProcessInfo
}

func init() {

}

func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/devices/virtual/dmi/id/product_uuid"} {
		payload, err := os.ReadFile(proc.HostPath(p))
		if err != nil {
			klog.Warningln("failed to read machine-id:", err)
			continue
		}
		id := strings.TrimSpace(strings.Replace(string(payload), "-", "", -1))
		klog.Infoln("machine-id: ", id)
		return id
	}
	return ""
}

func systemUUID() string {
	payload, err := os.ReadFile(proc.HostPath("/sys/devices/virtual/dmi/id/product_uuid"))
	if err != nil {
		klog.Warningln("failed to read system-uuid:", err)
		return ""
	}
	return strings.TrimSpace(string(payload))
}

func (mgr *Manager) setNamespace() error {
	ns, err := GetSelfNetNs()
	if err != nil {
		return fmt.Errorf("Get Self Network Namespace Failed, %v \n", err)
	}
	mgr.selfNetNs = ns

	hostNetNs, err := GetHostNetNs()
	if err != nil {
		return fmt.Errorf("Get Host Network Namespace Failed %v \n", err)
	}
	mgr.hostNetNs = hostNetNs
	mgr.hostNetNsId = hostNetNs.UniqueId()

	return nil
}

func NewManager() *Manager {
	cg, err := NewFromProcessCgroupFile("/proc/self/cgroup")
	if err != nil {
		return nil
	}
	m := &Manager{
		hostNetNsId: netns.None().UniqueId(),
		selfNetNs:   netns.None(),
		agentPid:    uint32(os.Getpid()),
		cgroup:      cg,
	}
	return m
}

func (mgr *Manager) Init() error {

	if err := mgr.setNamespace(); err != nil {
		return fmt.Errorf("Set Namespace Failed %v \n", err)
	}

	err := proc.ExecuteInNetNs(mgr.hostNetNs, mgr.selfNetNs, func() error {
		if err := TaskstatsInit(); err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		return err
	}

	if err := SetCgroupNamespace(mgr.hostNetNs, mgr.selfNetNs); err != nil {
		return fmt.Errorf("Set Cgroup Namespace Failed %v \n", err)
	}

	mgr.machineId = machineID()
	mgr.systemUUID = systemUUID()
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return fmt.Errorf("init Uname Failed %v \n", err)
	}
	mgr.hostname = string(bytes.Split(utsname.Nodename[:], []byte{0})[0])

	whitelistNodeExternalNetworks()

	return nil
}

func (mgr *Manager) Run() error {
	var g errgroup.Group

	if err := mgr.Init(); err != nil {
		return fmt.Errorf("init Failed %v \n", err)
	}

	g.Go(func() error {
		fmt.Println("Run Profiling")

		mgr.processInfoCh = profiling.Init(mgr.machineId, mgr.hostname)
		reg := prometheus.NewRegistry()
		so := ebpfspy.SessionOptions{
			CollectUser:               true,
			CollectKernel:             false,
			UnknownSymbolModuleOffset: true,
			UnknownSymbolAddress:      false,
			PythonEnabled:             true,
			CacheOptions: symtab.CacheOptions{
				PidCacheOptions: symtab.GCacheOptions{
					Size:       256,
					KeepRounds: 8,
				},
				BuildIDCacheOptions: symtab.GCacheOptions{
					Size:       256,
					KeepRounds: 8,
				},
				SameFileCacheOptions: symtab.GCacheOptions{
					Size:       256,
					KeepRounds: 8,
				},
				SymbolOptions: symtab.SymbolOptions{
					GoTableFallback:    true,
					PythonFullFilePath: false,
					DemangleOptions:    elf.DemangleFull,
				},
			},
			Metrics: &metrics.Metrics{
				Symtab: metrics.NewSymtabMetrics(reg),
				Python: metrics.NewPythonMetrics(reg),
			},
			SampleRate: SampleRate,
		}
		var err error
		session, err = ebpfspy.NewSession(log.NewNopLogger(), ProcessTargetFinder, so)
		if err != nil {
			klog.Errorln(err)
			session = nil
			return nil
		}
		err = session.Start()
		if err != nil {
			klog.Errorln(err)
			session = nil
			return nil
		}
		go collect()

		processInfoCh := make(chan containers.ProcessInfo)
		//targetFinder.start(processInfoCh)
		ProcessTargetFinder.start(processInfoCh)
		//return processInfoCh

		return nil
	})

	if err := g.Wait(); err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Successfully fetched all URLs.")
	}

	return nil

}

func main() {

	if err := NewManager().Run(); err != nil {
		klog.Fatalf("Run Failed %v \n", err)
	}

	// 컨텍스트와 취소 함수 생성
	ctx, cancel := context.WithCancel(context.Background())

	// 채널을 통해 시그널을 수신
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// 고루틴에서 시그널 대기
	go func() {
		sig := <-signalChan
		fmt.Printf("Received signal: %s\n", sig)
		cancel() // 컨텍스트 취소
	}()

	fmt.Println("Waiting for signal...")
	<-ctx.Done() // 컨텍스트가 취소될 때까지 대기

}

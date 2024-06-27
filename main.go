package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/vishvananda/netns"
	"golang.org/x/sync/errgroup"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/coroot/coroot-node-agent/proc"
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

	hostname      string
	kernelVersion string
	systemUUID    string
	machineId     string

	hostConntrack *Conntrack
	events        chan ebpftracer.Event
	tracer        *ebpftracer.Tracer

	agentPid             uint32
	containerIdRegexp    *regexp.Regexp
	containersById       map[ContainerID]*Container
	containersByCgroupId map[string]*Container
	containersByPid      map[uint32]*Container
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
		hostNetNsId:          netns.None().UniqueId(),
		selfNetNs:            netns.None(),
		agentPid:             uint32(os.Getpid()),
		containerIdRegexp:    regexp.MustCompile(`[a-z0-9]{64}`),
		cgroup:               cg,
		containersById:       map[ContainerID]*Container{},
		containersByCgroupId: map[string]*Container{},
		containersByPid:      map[uint32]*Container{},
	}
	return m
}

func (mgr *Manager) Init() error {

	if err := mgr.setNamespace(); err != nil {
		return fmt.Errorf("Set Namespace Failed %v \n", err)
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
	mgr.kernelVersion = string(bytes.Split(utsname.Release[:], []byte{0})[0])
	whitelistNodeExternalNetworks()

	mgr.tracer = ebpftracer.NewTracer(mgr.kernelVersion, *flags.DisableL7Tracing)

	return nil
}

func (mgr *Manager) Run() error {
	var g errgroup.Group

	if err := mgr.Init(); err != nil {
		return fmt.Errorf("init Failed %v \n", err)
	}

	g.Go(func() error {

		if err := DockerdInit(); err != nil {
			klog.Warningln(err)
		}
		if err := ContainerdInit(); err != nil {
			klog.Warningln(err)
		}
		if err := CrioInit(); err != nil {
			klog.Warningln(err)
		}
		if err := JournaldInit(); err != nil {
			klog.Warningln(err)
		}
		ct, err := NewConntrack(mgr.hostNetNs)
		if err != nil {
			return nil
		}
		mgr.hostConntrack = ct
		mgr.events = make(chan ebpftracer.Event, 10000)

		go mgr.handleEvents(mgr.events)
		if err = mgr.tracer.Run(mgr.events); err != nil {
			close(mgr.events)
			return nil
		}

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

func (r *Manager) handleEvents(ch <-chan ebpftracer.Event) {
	gcTicker := time.NewTicker(gcInterval)
	defer gcTicker.Stop()
	for {
		select {
		case now := <-gcTicker.C:
			for pid, c := range r.containersByPid {
				cg, err := proc.ReadCgroup(pid)
				if err != nil {
					delete(r.containersByPid, pid)
					if c != nil {
						c.onProcessExit(pid, false)
					}
					continue
				}
				if c != nil && cg.Id != c.cgroup.Id {
					delete(r.containersByPid, pid)
					c.onProcessExit(pid, false)
				}
			}
			activeIPs := map[netaddr.IP]struct{}{}
			for id, c := range r.containersById {
				for dst := range c.connectLastAttempt {
					activeIPs[dst.IP()] = struct{}{}
				}
				if !c.Dead(now) {
					continue
				}
				klog.Infoln("deleting dead container:", id)
				for cg, cc := range r.containersByCgroupId {
					if cc == c {
						delete(r.containersByCgroupId, cg)
					}
				}
				for pid, cc := range r.containersByPid {
					if cc == c {
						delete(r.containersByPid, pid)
					}
				}
				//if ok := prometheus.WrapRegistererWith(prometheus.Labels{"container_id": string(id)}, r.reg).Unregister(c); !ok {
				//	klog.Warningln("failed to unregister container:", id)
				//}
				delete(r.containersById, id)
				c.Close()
			}
			//r.ip2fqdnLock.Lock()
			//for ip := range r.ip2fqdn {
			//	if _, ok := activeIPs[ip]; !ok {
			//		delete(r.ip2fqdn, ip)
			//	}
			//}
			//r.ip2fqdnLock.Unlock()
		case e, more := <-ch:
			if !more {
				return
			}
			switch e.Type {
			case ebpftracer.EventTypeProcessStart:
				c, seen := r.containersByPid[e.Pid]
				switch { // possible pids wraparound + missed `process-exit` event
				case c == nil && seen: // ignored
					delete(r.containersByPid, e.Pid)
				case c != nil: // revalidating by cgroup
					cg, err := proc.ReadCgroup(e.Pid)
					if err != nil || cg.Id != c.cgroup.Id {
						delete(r.containersByPid, e.Pid)
						c.onProcessExit(e.Pid, false)
					}
				}
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					p := c.onProcessStart(e.Pid)
					if p != nil {
						fmt.Printf("EventTypeProcessStart pid: %v container id : %v, started at : %v \n",
							p.Pid, c.id, p.StartedAt)
					}

					//if r.processInfoCh != nil && p != nil {
					//	r.processInfoCh <- ProcessInfo{Pid: p.Pid, ContainerId: c.id, StartedAt: p.StartedAt}
					//}
				}
			case ebpftracer.EventTypeProcessExit:
				if c := r.containersByPid[e.Pid]; c != nil {
					c.onProcessExit(e.Pid, e.Reason == ebpftracer.EventReasonOOMKill)
				}
				delete(r.containersByPid, e.Pid)

			case ebpftracer.EventTypeFileOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onFileOpen(e.Pid, e.Fd)
				}

			case ebpftracer.EventTypeListenOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onListenOpen(e.Pid, e.SrcAddr, false)
				} else {
					klog.Infoln("TCP listen open from unknown container", e)
				}
			case ebpftracer.EventTypeListenClose:
				if c := r.containersByPid[e.Pid]; c != nil {
					c.onListenClose(e.Pid, e.SrcAddr)
				}

			case ebpftracer.EventTypeConnectionOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onConnectionOpen(e.Pid, e.Fd, e.SrcAddr, e.DstAddr, e.Timestamp, false)
					c.attachTlsUprobes(r.tracer, e.Pid)
				} else {
					klog.Infoln("TCP connection from unknown container", e)
				}
			case ebpftracer.EventTypeConnectionError:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onConnectionOpen(e.Pid, e.Fd, e.SrcAddr, e.DstAddr, 0, true)
				} else {
					klog.Infoln("TCP connection error from unknown container", e)
				}
			case ebpftracer.EventTypeConnectionClose:
				srcDst := AddrPair{src: e.SrcAddr, dst: e.DstAddr}
				for _, c := range r.containersById {
					if c.onConnectionClose(srcDst) {
						break
					}
				}
			case ebpftracer.EventTypeTCPRetransmit:
				srcDst := AddrPair{src: e.SrcAddr, dst: e.DstAddr}
				for _, c := range r.containersById {
					if c.onRetransmit(srcDst) {
						break
					}
				}
			case ebpftracer.EventTypeL7Request:
				if e.L7Request == nil {
					continue
				}
				if c := r.containersByPid[e.Pid]; c != nil {
					ip2fqdn := c.onL7Request(e.Pid, e.Fd, e.Timestamp, e.L7Request)
					fmt.Printf("L7 Event Request : %v \n", ip2fqdn)
					//r.ip2fqdnLock.Lock()
					//for ip, fqdn := range ip2fqdn {
					//	r.ip2fqdn[ip] = fqdn
					//}
					//r.ip2fqdnLock.Unlock()
				}
			}
		}
	}
}

func (r *Manager) getOrCreateContainer(pid uint32) *Container {
	if c, seen := r.containersByPid[pid]; c != nil {
		return c
	} else if seen { // ignored
		return nil
	}
	cg, err := proc.ReadCgroup(pid)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Warningln("failed to read proc cgroup:", err)
		}
		return nil
	}
	if c := r.containersByCgroupId[cg.Id]; c != nil {
		r.containersByPid[pid] = c
		return c
	}
	if cg.ContainerType == cgroup.ContainerTypeSandbox {
		cmdline := proc.GetCmdline(pid)
		parts := bytes.Split(cmdline, []byte{0})
		if len(parts) > 0 {
			cmd := parts[0]
			lastArg := parts[len(parts)-1]
			if (bytes.HasSuffix(cmd, []byte("runsc-sandbox")) || bytes.HasSuffix(cmd, []byte("runsc"))) && r.containerIdRegexp.Match(lastArg) {
				cg.ContainerId = string(lastArg)
			}
		}
	}
	md, err := getContainerMetadata(cg)
	if err != nil {
		klog.Warningf("failed to get container metadata for pid %d -> %s: %s", pid, cg.Id, err)
		return nil
	}
	id := calcId(cg, md)
	klog.Infof("calculated container id %d -> %s -> %s", pid, cg.Id, id)
	if id == "" {
		if cg.Id == "/init.scope" && pid != 1 {
			klog.InfoS("ignoring without persisting", "cg", cg.Id, "pid", pid)
		} else {
			klog.InfoS("ignoring", "cg", cg.Id, "pid", pid)
			r.containersByPid[pid] = nil
		}
		return nil
	}
	if c := r.containersById[id]; c != nil {
		klog.Warningln("id conflict:", id)
		if cg.CreatedAt().After(c.cgroup.CreatedAt()) {
			c.cgroup = cg
			c.metadata = md
			c.runLogParser("")
			if c.nsConntrack != nil {
				_ = c.nsConntrack.Close()
				c.nsConntrack = nil
			}
		}
		r.containersByPid[pid] = c
		r.containersByCgroupId[cg.Id] = c
		return c
	}
	c, err := NewContainer(id, cg, md, r.hostConntrack, pid, r)
	if err != nil {
		klog.Warningf("failed to create container pid=%d cg=%s id=%s: %s", pid, cg.Id, id, err)
		return nil
	}

	klog.InfoS("detected a new container", "pid", pid, "cg", cg.Id, "id", id)
	//if err := prometheus.WrapRegistererWith(prometheus.Labels{"container_id": string(id)}, r.reg).Register(c); err != nil {
	//	klog.Warningln("failed to register container:", err)
	//	return nil
	//}
	r.containersByPid[pid] = c
	r.containersByCgroupId[cg.Id] = c
	r.containersById[id] = c
	return c
}
func calcId(cg *cgroup.Cgroup, md *ContainerMetadata) ContainerID {
	if cg.ContainerType == cgroup.ContainerTypeSystemdService {
		if strings.HasPrefix(cg.ContainerId, "/system.slice/crio-conmon-") {
			return ""
		}
		return ContainerID(cg.ContainerId)
	}
	switch cg.ContainerType {
	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeSandbox, cgroup.ContainerTypeCrio:
	default:
		return ""
	}
	if cg.ContainerId == "" {
		return ""
	}
	if md.labels["io.kubernetes.pod.name"] != "" {
		pod := md.labels["io.kubernetes.pod.name"]
		namespace := md.labels["io.kubernetes.pod.namespace"]
		name := md.labels["io.kubernetes.container.name"]
		if cg.ContainerType == cgroup.ContainerTypeSandbox {
			name = "sandbox"
		}
		if name == "" || name == "POD" { // skip pause containers
			return ""
		}
		return ContainerID(fmt.Sprintf("/k8s/%s/%s/%s", namespace, pod, name))
	}
	if taskNameParts := strings.SplitN(md.labels["com.docker.swarm.task.name"], ".", 3); len(taskNameParts) == 3 {
		namespace := md.labels["com.docker.stack.namespace"]
		service := md.labels["com.docker.swarm.service.name"]
		if namespace != "" {
			service = strings.TrimPrefix(service, namespace+"_")
		}
		if namespace == "" {
			namespace = "_"
		}
		return ContainerID(fmt.Sprintf("/swarm/%s/%s/%s", namespace, service, taskNameParts[1]))
	}
	if md.env != nil {
		allocId := md.env["NOMAD_ALLOC_ID"]
		group := md.env["NOMAD_GROUP_NAME"]
		job := md.env["NOMAD_JOB_NAME"]
		namespace := md.env["NOMAD_NAMESPACE"]
		task := md.env["NOMAD_TASK_NAME"]
		if allocId != "" && group != "" && job != "" && namespace != "" && task != "" {
			return ContainerID(fmt.Sprintf("/nomad/%s/%s/%s/%s/%s", namespace, job, group, allocId, task))
		}
	}
	if md.name == "" { // should be "pure" dockerd container here
		klog.Warningln("empty dockerd container name for:", cg.ContainerId)
		return ""
	}
	return ContainerID("/docker/" + md.name)
}
func getContainerMetadata(cg *cgroup.Cgroup) (*ContainerMetadata, error) {
	switch cg.ContainerType {
	case cgroup.ContainerTypeSystemdService:
		md := &ContainerMetadata{}
		md.systemdTriggeredBy = SystemdTriggeredBy(cg.ContainerId)
		return md, nil
	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeSandbox, cgroup.ContainerTypeCrio:
	default:
		return &ContainerMetadata{}, nil
	}
	if cg.ContainerId == "" {
		return &ContainerMetadata{}, nil
	}
	if cg.ContainerType == cgroup.ContainerTypeCrio {
		return CrioInspect(cg.ContainerId)
	}
	var dockerdErr error
	if dockerdClient != nil {
		md, err := DockerdInspect(cg.ContainerId)
		if err == nil {
			return md, nil
		}
		dockerdErr = err
	}
	var containerdErr error
	if containerdClient != nil {
		md, err := ContainerdInspect(cg.ContainerId)
		if err == nil {
			return md, nil
		}
		containerdErr = err
	}
	return nil, fmt.Errorf("failed to interact with dockerd (%s) or with containerd (%s)", dockerdErr, containerdErr)
}

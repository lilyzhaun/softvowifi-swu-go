package driver

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/iniwex5/netlink"
)

// XFRMManager 封装 Linux XFRM 子系统操作
type XFRMManager struct {
	undos      []func() error
	ops        xfrmNetlink
	mu         sync.Mutex
	states     map[stateKey]*ownedState
	policies   map[policyKey]*ownedPolicy
	generation uint64
	cleanupErr error
}

// NewXFRMManager 创建 XFRM 管理器
func NewXFRMManager() *XFRMManager {
	return &XFRMManager{ops: productionXFRM(), states: make(map[stateKey]*ownedState), policies: make(map[policyKey]*ownedPolicy)}
}

// FlushAll 清空所有 XFRM State 和 Policy（前置清理）
func (x *XFRMManager) FlushAll() {
	_ = netlink.XfrmStateFlush(0)
	_ = netlink.XfrmPolicyFlush()
}

// AddXFRMInterface 创建 XFRM 接口 (Linux 4.19+)
func (x *XFRMManager) AddXFRMInterface(name string, ifID uint32, underlyingIdx int) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if existing, _ := netlink.LinkByName(name); existing != nil {
		_ = netlink.LinkDel(existing)
	}
	xfrmi := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Ifid:      ifID,
	}
	if underlyingIdx > 0 {
		xfrmi.LinkAttrs.ParentIndex = underlyingIdx
	}
	if err := netlink.LinkAdd(xfrmi); err != nil {
		return fmt.Errorf("创建 XFRM 接口 %s 失败: %v", name, err)
	}
	x.undos = append(x.undos, func() error { return x.DelXFRMInterface(name) })
	return nil
}

// DelXFRMInterface 删除 XFRM 接口
func (x *XFRMManager) DelXFRMInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("删除 XFRM 接口 %s 失败: %v", name, err)
	}
	return nil
}

// AddSA 添加 XFRM Security Association
func (x *XFRMManager) AddSA(cfg XFRMSAConfig) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.addOwnedState(x.buildXfrmState(cfg))
}

// DelSA 删除 XFRM SA（幂等）
func (x *XFRMManager) DelSA(spi uint32, src, dst net.IP, proto netlink.Proto) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	key := stateIdentity(&netlink.XfrmState{Dst: dst, Proto: proto, Spi: int(spi)})
	return x.deleteOwnedState(key, 0)
}

// FlushByIP 仅清理本实例登记的端点关联 SA/SP；失败记录保留供重试。
func (x *XFRMManager) FlushByIP(ip net.IP) {
	if ip == nil {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.cleanupErr = x.cleanupOwned(ip.String())
}

// GetSALastUsed 查询 SA 最后使用时间
func (x *XFRMManager) GetSALastUsed(spi uint32, src, dst net.IP, proto netlink.Proto) (uint64, error) {
	state := &netlink.XfrmState{Src: src, Dst: dst, Proto: proto, Spi: int(spi)}
	s, err := x.ops.stateGet(state)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return 0, nil
		}
		return 0, fmt.Errorf("读取 XFRM SA (spi=0x%x) 状态失败: %v", spi, err)
	}
	return s.Statistics.UseTime, nil
}

// AddSP 添加/更新 XFRM Security Policy
func (x *XFRMManager) AddSP(cfg XFRMSPConfig) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.addOwnedPolicy(x.buildXfrmPolicy(cfg))
}

// DelSP 删除 XFRM Security Policy（幂等）
func (x *XFRMManager) DelSP(cfg XFRMSPConfig) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.deleteOwnedPolicy(policyIdentity(x.buildXfrmPolicy(cfg)), 0)
}

func (x *XFRMManager) CleanupOwned() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.cleanupErr = x.cleanupOwned("")
	return x.cleanupErr
}

// Cleanup 逆序回滚
func (x *XFRMManager) Cleanup() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.cleanupErr = x.cleanupOwned("")
	for i := len(x.undos) - 1; i >= 0; i-- {
		if err := x.undos[i](); err != nil {
			x.cleanupErr = errors.Join(x.cleanupErr, err)
		} else {
			x.undos = append(x.undos[:i], x.undos[i+1:]...)
		}
	}
}

// UndoFuncs 返回回滚函数
func (x *XFRMManager) UndoFuncs() []func() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.ownedUndoFuncs()
}

// UpdateSA 更新现有 SA
func (x *XFRMManager) UpdateSA(cfg XFRMSAConfig) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.updateOwnedState(cfg)
}

// UpdateSP 更新现有 SP
func (x *XFRMManager) UpdateSP(cfg XFRMSPConfig) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.updateOwnedPolicy(x.buildXfrmPolicy(cfg))
}

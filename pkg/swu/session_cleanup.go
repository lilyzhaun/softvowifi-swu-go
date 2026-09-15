package swu

import (
	"errors"

	"github.com/1239t/swu-go/pkg/logger"
)

var ErrCleanup = errors.New("session network cleanup incomplete")

func (s *Session) cleanupNetworkConfig() error {
	s.closeNetstackDataplane()
	if s.xfrmMgr != nil {
		if err := s.xfrmMgr.CleanupOwned(); err != nil {
			s.Logger.Error("XFRM 清理未完成，保留网络清理责任", logger.Err(err))
			return errors.Join(ErrCleanup, err)
		}
	}
	for len(s.netUndos) > 0 {
		index := len(s.netUndos) - 1
		if err := s.netUndos[index](); err != nil {
			s.Logger.Error("网络清理未完成，保留待处理操作", logger.Err(err))
			return errors.Join(ErrCleanup, err)
		}
		s.netUndos[index] = nil
		s.netUndos = s.netUndos[:index]
	}
	s.Logger.Info("网络配置清理完成")
	return nil
}

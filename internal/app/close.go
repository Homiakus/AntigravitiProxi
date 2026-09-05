package app

import "context"

// Close stops the managed sing-box helper and waits for route/TUN cleanup.
// It is safe to call when no proxy is running.
func (s *Server) Close(ctx context.Context) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.pm.StopAndWait(ctx)
}

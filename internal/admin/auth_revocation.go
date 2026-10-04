package admin

// revokeUserCredentials 让某个账号的全部 refresh 与活跃 access 凭据立即失效。
func revokeUserCredentials(d *AuthDeps, username, reason string) error {
	if d == nil {
		return nil
	}
	var firstErr error
	if d.RTRepo != nil {
		if err := d.RTRepo.RevokeByUsername(username); err != nil {
			firstErr = err
		}
	}
	if d.SessionMgr == nil {
		return firstErr
	}

	sessions := d.SessionMgr.ListUserSessions(username)
	d.SessionMgr.RemoveUserSessions(username)
	if d.TokenMgr != nil {
		for _, session := range sessions {
			if err := d.TokenMgr.BlacklistTokenChecked(session.JTI, session.ExpiresAt, reason); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

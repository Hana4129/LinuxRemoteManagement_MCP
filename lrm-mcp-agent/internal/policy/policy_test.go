package policy

import "testing"

func newTestEngine() *Engine {
	global := GlobalPolicy{
		Commands:      []string{"/usr/bin/systemctl restart nginx"},
		Services:      []string{"nginx", "docker"},
		AllowedPaths:  []string{"/etc/", "/var/log/"},
		DeniedPaths:   []string{"/etc/shadow", "/etc/sudoers"},
		MaxFileSizeMB: 10,
	}
	e := NewEngine(global)
	e.AddToken(TokenPolicy{ID: "ro", Name: "readonly", Scope: ScopeReadonly})
	e.AddToken(TokenPolicy{ID: "op", Name: "operator", Scope: ScopeOperator,
		Commands: []string{"/usr/bin/systemctl restart docker"},
		Services: []string{"nginx"},
		Files:    []string{"/etc/nginx/nginx.conf"},
	})
	e.AddToken(TokenPolicy{ID: "off", Name: "disabled", Scope: ScopeOperator, Disabled: true})
	return e
}

func TestCanReadFile(t *testing.T) {
	e := newTestEngine()
	if ok, _ := e.CanReadFile("ro", "/etc/os-release"); !ok {
		t.Error("global allowlist /etc/ should be readable")
	}
	if ok, _ := e.CanReadFile("ro", "/home/user/.ssh/id_rsa"); ok {
		t.Error("path outside allowlist must be denied")
	}
	if ok, _ := e.CanReadFile("ro", "/etc/shadow"); ok {
		t.Error("denied_paths must be denied even inside allowlist")
	}
	if ok, _ := e.CanReadFile("op", "/etc/nginx/nginx.conf"); !ok {
		t.Error("token allowlisted file should be readable")
	}
	if ok, _ := e.CanReadFile("op", "/var/log/syslog"); ok {
		t.Error("token allowlist set: non-listed file must be denied")
	}
	if ok, _ := e.CanReadFile("ro", "/etc/../etc/shadow"); ok {
		t.Error("traversal into denied path must be denied")
	}
}

func TestCanManageService(t *testing.T) {
	e := newTestEngine()
	if ok, _ := e.CanManageService("ro", "nginx"); ok {
		t.Error("readonly token must not manage services")
	}
	if ok, _ := e.CanManageService("op", "nginx"); !ok {
		t.Error("operator with allowlisted service should manage it")
	}
	if ok, _ := e.CanManageService("op", "docker"); ok {
		t.Error("token allowlist set: non-listed service must be denied for manage")
	}
	if ok, _ := e.CanManageService("off", "nginx"); ok {
		t.Error("disabled token must be denied")
	}
}

func TestCanReadService(t *testing.T) {
	e := newTestEngine()
	if ok, _ := e.CanReadService("ro", "nginx"); !ok {
		t.Error("readonly token should read allowlisted service status")
	}
	if ok, _ := e.CanReadService("ro", "unknown-svc"); ok {
		t.Error("non-allowlisted service must be denied")
	}
}

func TestCanRunCommand(t *testing.T) {
	e := newTestEngine()
	if ok, _ := e.CanRunCommand("ro", "/usr/bin/systemctl restart nginx"); ok {
		t.Error("readonly token must not run commands")
	}
	if ok, _ := e.CanRunCommand("op", "/usr/bin/systemctl restart docker"); !ok {
		t.Error("operator token-allowlisted command should run")
	}
	if ok, _ := e.CanRunCommand("op", "/usr/bin/systemctl restart nginx"); ok {
		t.Error("token allowlist set: non-listed command must be denied")
	}
	if ok, _ := e.CanRunCommand("op", "rm -rf /"); ok {
		t.Error("deny by default: arbitrary command must be denied")
	}
}

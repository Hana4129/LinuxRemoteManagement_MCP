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

func newWriteTestEngine() *Engine {
	global := GlobalPolicy{
		WritePaths:  []string{"/var/tmp/", "/opt/app/config/"},
		DeniedPaths: []string{"/etc/shadow"},
	}
	e := NewEngine(global)
	e.AddToken(TokenPolicy{ID: "ro", Name: "readonly", Scope: ScopeReadonly})
	e.AddToken(TokenPolicy{ID: "op", Name: "operator", Scope: ScopeOperator})
	e.AddToken(TokenPolicy{ID: "off", Name: "disabled", Scope: ScopeOperator, Disabled: true})
	return e
}

func TestCanWriteFile(t *testing.T) {
	e := newWriteTestEngine()

	// operator は write_paths 配下に書ける
	if ok, _ := e.CanWriteFile("op", "/var/tmp/test.txt"); !ok {
		t.Error("operator should write inside write_paths")
	}
	// readonly は書けない
	if ok, _ := e.CanWriteFile("ro", "/var/tmp/test.txt"); ok {
		t.Error("readonly token must not write files")
	}
	// disabled トークンは書けない
	if ok, _ := e.CanWriteFile("off", "/var/tmp/test.txt"); ok {
		t.Error("disabled token must be denied")
	}
	// write_paths 外は拒否
	if ok, _ := e.CanWriteFile("op", "/etc/passwd"); ok {
		t.Error("path outside write_paths must be denied")
	}
	// denied_paths は write_paths 内でも優先して拒否される
}

func TestCanWriteFile_DenyByDefault(t *testing.T) {
	// write_paths 未設定ならすべて拒否
	e := NewEngine(GlobalPolicy{})
	e.AddToken(TokenPolicy{ID: "op", Name: "operator", Scope: ScopeOperator})
	if ok, _ := e.CanWriteFile("op", "/var/tmp/test.txt"); ok {
		t.Error("deny by default: no write_paths configured must deny")
	}
}

func TestCanWriteFile_DeniedPathsPrecedence(t *testing.T) {
	// denied_paths は write_paths 内のパスでも優先して拒否
	e := NewEngine(GlobalPolicy{
		WritePaths:  []string{"/etc/"},
		DeniedPaths: []string{"/etc/shadow"},
	})
	e.AddToken(TokenPolicy{ID: "op", Name: "operator", Scope: ScopeOperator})
	if ok, _ := e.CanWriteFile("op", "/etc/nginx/nginx.conf"); !ok {
		t.Error("write_paths inside should be writable")
	}
	if ok, _ := e.CanWriteFile("op", "/etc/shadow"); ok {
		t.Error("denied_paths must be denied even inside write_paths")
	}
}


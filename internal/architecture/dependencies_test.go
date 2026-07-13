package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/ai-matrix-meta/tailscale-gateway-agent"

var approvedAdapterImportPrefixes = []string{
	"github.com/google/nftables",
	"github.com/mdlayher/netlink",
	"github.com/prometheus/client_golang",
	"github.com/vishvananda/netlink",
	"golang.org/x/sys",
	"k8s.io/apimachinery",
	"k8s.io/client-go",
	"tailscale.com",
}

func TestInternalDependencyDirection(t *testing.T) {
	root := moduleRoot(t)
	allowed := map[string]map[string]bool{
		"cmd":         {"bootstrap": true},
		"bootstrap":   {"application": true, "adapter": true},
		"application": {"port": true, "domain": true},
		"adapter":     {"port": true, "domain": true},
		"port":        {"domain": true},
		"domain":      {},
	}

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		sourceLayer := layerOf(relative)
		if sourceLayer == "architecture" {
			return nil
		}
		if sourceLayer == "" {
			if strings.HasSuffix(relative, "_test.go") && strings.HasPrefix(relative, "integration/") {
				return nil
			}
			t.Errorf("production Go file %s is outside the declared architecture", relative)
			return nil
		}
		sourcePackage := internalPackage(relative)
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if importPath == "os/exec" && sourcePackage != "adapter/process" {
				t.Errorf("%s imports os/exec outside the process adapter boundary", relative)
			}
			if !strings.HasPrefix(importPath, modulePath+"/") {
				if isThirdPartyImport(importPath) {
					if sourceLayer != "adapter" {
						t.Errorf("%s file %s imports third-party package %s outside an adapter", sourceLayer, relative, importPath)
					} else if !hasApprovedPrefix(importPath, approvedAdapterImportPrefixes) {
						t.Errorf("adapter file %s imports unapproved third-party package %s", relative, importPath)
					}
				}
				continue
			}
			targetRelative := strings.TrimPrefix(importPath, modulePath+"/")
			targetLayer := layerOf(targetRelative)
			if targetLayer == "" || targetLayer == "architecture" {
				t.Errorf("%s imports package outside the declared production architecture: %s", relative, importPath)
				continue
			}
			if targetLayer == sourceLayer {
				targetPackage := internalPackage(targetRelative)
				if sourcePackage == targetPackage {
					continue
				}
				switch sourceLayer {
				case "adapter":
					t.Errorf("adapter %s imports peer adapter %s in %s", sourcePackage, targetPackage, relative)
				case "application":
					t.Errorf("application package %s imports undeclared peer %s in %s", sourcePackage, targetPackage, relative)
				default:
					t.Errorf("layer %s package %s imports peer %s in %s", sourceLayer, sourcePackage, targetPackage, relative)
				}
				continue
			}
			if !allowed[sourceLayer][targetLayer] {
				t.Errorf("prohibited dependency %s -> %s in %s (import %s)", sourceLayer, targetLayer, relative, importPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
}

func TestNoExternalNetworkCommandExecution(t *testing.T) {
	root := moduleRoot(t)
	forbidden := map[string]bool{
		"ip": true, "nft": true, "iptables": true, "kubectl": true,
		"tailscale": true, "awk": true, "jq": true, "sh": true, "bash": true,
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return walkErr
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext") {
				return true
			}
			packageName, ok := selector.X.(*ast.Ident)
			if !ok || packageName.Name != "exec" {
				return true
			}
			argumentIndex := 0
			if selector.Sel.Name == "CommandContext" {
				argumentIndex = 1
			}
			if len(call.Args) <= argumentIndex {
				return true
			}
			literal, ok := call.Args[argumentIndex].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr == nil && forbidden[value] {
				t.Errorf("%s contains forbidden external network command literal %q", path, value)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
}

func TestNoHardCodedExecutionEnvironmentContracts(t *testing.T) {
	root := moduleRoot(t)
	forbidden := []string{
		"eth" + "0",
		"tun" + "0",
		"tailscale" + "0",
		"Pod" + "Interface",
		"POD" + "_NETWORK",
		"Interface" + "WaitTimeout",
		"GATEWAY_DATAPLANE_" + "POD_NETWORK_SETTING_INTERFACE",
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		extension := strings.ToLower(filepath.Ext(path))
		if !slices.Contains([]string{".go", ".md", ".yaml", ".yml", ".json", ".jsonc"}, extension) && entry.Name() != "Dockerfile" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, contract := range forbidden {
			if strings.Contains(string(content), contract) {
				relative, _ := filepath.Rel(root, path)
				t.Errorf("%s contains prohibited execution-environment contract %q", relative, contract)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan module: %v", err)
	}
}

func TestArchitecturePathClassificationFailsClosed(t *testing.T) {
	tests := []struct {
		path  string
		layer string
		pkg   string
	}{
		{path: "cmd/tailscale-gateway-agent/main.go", layer: "cmd", pkg: "cmd/tailscale-gateway-agent"},
		{path: "internal/application/reconciler.go", layer: "application", pkg: "application"},
		{path: "internal/application/capability/monitor.go", layer: "application", pkg: "application/capability"},
		{path: "internal/adapter/netlink/netlink_linux.go", layer: "adapter", pkg: "adapter/netlink"},
		{path: "internal/unowned/runtime.go", layer: "", pkg: "unowned"},
		{path: "experimental/runtime.go", layer: "", pkg: ""},
	}
	for _, test := range tests {
		if got := layerOf(test.path); got != test.layer {
			t.Errorf("layerOf(%q) = %q, want %q", test.path, got, test.layer)
		}
		if got := internalPackage(test.path); got != test.pkg {
			t.Errorf("internalPackage(%q) = %q, want %q", test.path, got, test.pkg)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("resolve module root %s: %v", root, err)
	}
	return root
}

func layerOf(relative string) string {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) == 0 {
		return ""
	}
	if parts[0] == "cmd" {
		return "cmd"
	}
	if len(parts) >= 2 && parts[0] == "internal" {
		switch parts[1] {
		case "bootstrap", "application", "adapter", "port", "domain", "architecture":
			return parts[1]
		}
	}
	return ""
}

func internalPackage(relative string) string {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) > 0 && strings.HasSuffix(parts[len(parts)-1], ".go") {
		parts = parts[:len(parts)-1]
	}
	if len(parts) >= 2 && parts[0] == "cmd" {
		return strings.Join(parts, "/")
	}
	if len(parts) < 2 || parts[0] != "internal" {
		return ""
	}
	return strings.Join(parts[1:], "/")
}

func isThirdPartyImport(importPath string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	return strings.Contains(first, ".")
}

func hasApprovedPrefix(importPath string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
			return true
		}
	}
	return false
}

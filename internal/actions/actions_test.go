package actions

import "testing"

func TestValidateArgs(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		args    []string
		wantErr bool
	}{
		{name: "restart container ok", action: "restart_container", args: []string{"app"}, wantErr: false},
		{name: "restart container missing arg", action: "restart_container", args: nil, wantErr: true},
		{name: "rollback extra args", action: "rollback_release", args: []string{"app", "image:v1", "--debug", "extra"}, wantErr: true},
		{name: "host check no args", action: "check_host_health", args: nil, wantErr: false},
		{name: "unknown action", action: "deploy_release", args: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArgs(tt.action, tt.args)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestNamesSorted(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("expected names")
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("names are not sorted: %v", names)
		}
	}
}

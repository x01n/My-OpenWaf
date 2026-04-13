package core

import "testing"

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid sqlite",
			cfg: Config{
				DBDriver:  "sqlite",
				DBDSN:     "./data/waf.db",
				AdminBind: ":9443",
			},
			wantErr: false,
		},
		{
			name: "valid mysql",
			cfg: Config{
				DBDriver:  "mysql",
				DBDSN:     "root:pass@tcp(localhost:3306)/waf",
				AdminBind: ":9443",
			},
			wantErr: false,
		},
		{
			name: "invalid driver",
			cfg: Config{
				DBDriver:  "oracle",
				DBDSN:     "foo",
				AdminBind: ":9443",
			},
			wantErr: true,
		},
		{
			name: "empty dsn",
			cfg: Config{
				DBDriver:  "sqlite",
				DBDSN:     "",
				AdminBind: ":9443",
			},
			wantErr: true,
		},
		{
			name: "invalid admin bind",
			cfg: Config{
				DBDriver:  "sqlite",
				DBDSN:     "waf.db",
				AdminBind: "not-a-port",
			},
			wantErr: true,
		},
		{
			name: "invalid redis addr",
			cfg: Config{
				DBDriver:  "sqlite",
				DBDSN:     "waf.db",
				AdminBind: ":9443",
				RedisAddr: "bad-addr",
			},
			wantErr: true,
		},
		{
			name: "valid with redis",
			cfg: Config{
				DBDriver:  "sqlite",
				DBDSN:     "waf.db",
				AdminBind: ":9443",
				RedisAddr: "localhost:6379",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateWarnings(t *testing.T) {
	cfg := Config{
		DBDriver:  "sqlite",
		DBDSN:     "host=localhost dbname=waf",
		AdminBind: ":80",
	}
	warnings, err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) < 2 {
		t.Errorf("expected at least 2 warnings (dsn mismatch + well-known port), got %d", len(warnings))
	}
}

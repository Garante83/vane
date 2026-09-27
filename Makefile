VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0")
LDFLAGS = -s -w -X main.Version=$(VERSION)

.PHONY: build build-enterprise run clean install install-enterprise uninstall release test

# Standardaktion: Kompiliert das Projekt in die ausführbare Datei 'vane' (Home/Private-Modus mit Sweep)
build:
	go build -ldflags "$(LDFLAGS)" -o vane ./cmd/vane

# Enterprise-Aktion: Kompiliert das Projekt OHNE aktive Netzwerk-Sweeps (Unternehmensfreundlich)
build-enterprise:
	go build -tags nosweep -ldflags "$(LDFLAGS)" -o vane ./cmd/vane

# Führt alle Unit-Tests, Integrations-Smoke-Tests und Go Report Card Qualitätsprüfungen aus
test:
	@echo "[vane] Führe Go Report Card Qualitätsprüfungen aus (gofmt & go vet)..."
	@if [ -n "$$(gofmt -s -l .)" ]; then \
		echo "[vane] ❌ Fehler: Einige Go-Dateien sind nicht standardgemäß formatiert. Bitte führe 'gofmt -s -w .' aus!"; \
		gofmt -s -l .; \
		exit 1; \
	fi
	@go vet ./...
	@echo "[vane] Führe die gesamte Test-Suite aus..."
	go test -v -count=1 ./...
	@echo "[vane] Führe Integrations-Smoke-Tests aus..."
	./smoke_test.sh


# Führt das Projekt direkt aus (ohne eine bleibende Datei zu erzeugen)
run:
	go run ./cmd/vane $(ARGS)

# Installiert vane global im System, so dass es von überall aufgerufen werden kann (Home/Private-Modus)
install: build
	sudo install -m 755 vane /usr/local/bin/vane
	@echo "[vane] Erfolgreich global als 'vane' installiert!"

# Installiert die Enterprise-Version von vane global im System (sweepsicher)
install-enterprise: build-enterprise
	sudo install -m 755 vane /usr/local/bin/vane
	@echo "[vane] Erfolgreich global als sweepsicheres 'vane' (Enterprise) installiert!"

# Deinstalliert vane global aus dem System
uninstall:
	sudo rm -f /usr/local/bin/vane
	@echo "[vane] Global deinstalliert."

# Erstellt optimierte Cross-Plattform-Binärdateien für Releases im 'dist'-Ordner
release: test
	@echo "[vane] Kompiliere Cross-Plattform-Releases..."
	@mkdir -p dist
	# Linux
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/vane-linux-amd64 ./cmd/vane
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/vane-linux-arm64 ./cmd/vane
	# macOS
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/vane-darwin-amd64 ./cmd/vane
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/vane-darwin-arm64 ./cmd/vane
	# Windows
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/vane-windows-amd64.exe ./cmd/vane
	@echo "[vane] Alle Binaries erfolgreich in 'dist/' erstellt!"

# Bereinigt lokale kompilierte Artefakte
clean:
	rm -f vane
	rm -rf dist


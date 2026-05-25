.PHONY: build run clean install uninstall release

# Standardaktion: Kompiliert das Projekt in die ausführbare Datei 'vane'
build:
	go build -o vane cmd/vane/main.go

# Führt das Projekt direkt aus (ohne eine bleibende Datei zu erzeugen)
run:
	go run cmd/vane/main.go $(ARGS)

# Installiert vane global im System, so dass es von überall aufgerufen werden kann
install: build
	sudo install -m 755 vane /usr/local/bin/vane
	@echo "[vane] Erfolgreich global als 'vane' installiert!"

# Deinstalliert vane global aus dem System
uninstall:
	sudo rm -f /usr/local/bin/vane
	@echo "[vane] Global deinstalliert."

# Erstellt optimierte Cross-Plattform-Binärdateien für Releases im 'dist'-Ordner
release:
	@echo "[vane] Kompiliere Cross-Plattform-Releases..."
	@mkdir -p dist
	# Linux
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/vane-linux-amd64 cmd/vane/main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/vane-linux-arm64 cmd/vane/main.go
	# macOS
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o dist/vane-darwin-amd64 cmd/vane/main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o dist/vane-darwin-arm64 cmd/vane/main.go
	# Windows
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/vane-windows-amd64.exe cmd/vane/main.go
	@echo "[vane] Alle Binaries erfolgreich in 'dist/' erstellt!"

# Bereinigt lokale kompilierte Artefakte
clean:
	rm -f vane
	rm -rf dist


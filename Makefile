.PHONY: build run clean install uninstall

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

# Bereinigt lokale kompilierte Artefakte
clean:
	rm -f vane

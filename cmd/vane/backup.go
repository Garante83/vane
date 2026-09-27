package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"vane/pkg/util"
	"vane/pkg/vssd"
)

func handleBackupRescueMenu(reader *bufio.Reader, path, corrPath string) {
	for {
		fmt.Print("\x1b[H\x1b[2J") // Clear screen
		fmt.Println("┌" + strings.Repeat("─", 72) + "┐")
		if util.GetSystemLanguage() == "de" {
			fmt.Println("│  \x1b[1;31mvane ─ Menü zur Rettung beschädigter Cache-Dateien\x1b[0m                  │")
		} else {
			fmt.Println("│  \x1b[1;31mvane ─ Corrupted Cache Recovery Assistant\x1b[0m                       │")
		}
		fmt.Println("└" + strings.Repeat("─", 72) + "┘")

		if util.GetSystemLanguage() == "de" {
			fmt.Println("\n  Eine beschädigte Cache-Datei wurde im Hintergrund gesichert.")
			fmt.Println("  Wie möchtest du vorgehen?")
			fmt.Println()
			fmt.Println("    \x1b[1;33m[1]\x1b[0m Automatische Reparatur versuchen (Kommas, Klammern etc. heilen)")
			fmt.Println("    \x1b[1;33m[2]\x1b[0m Backup-Datei im System-Texteditor öffnen (nano/vi)")
			fmt.Println("    \x1b[1;33m[3]\x1b[0m Backup-Datei löschen (Verwerfen)")
			fmt.Println("    \x1b[1;33m[Q]\x1b[0m Zurück zum Hauptmenü (Back)")
		} else {
			fmt.Println("\n  A corrupted cache file was backed up in the background.")
			fmt.Println("  What would you like to do?")
			fmt.Println()
			fmt.Println("    \x1b[1;33m[1]\x1b[0m Attempt automatic repair (heals missing commas, braces, etc.)")
			fmt.Println("    \x1b[1;33m[2]\x1b[0m Open backup file in system text editor (nano/vi)")
			fmt.Println("    \x1b[1;33m[3]\x1b[0m Delete backup file (Discard)")
			fmt.Println("    \x1b[1;33m[Q]\x1b[0m Back to main menu")
		}

		fmt.Print("\n  \x1b[1;37mAuswahl:\x1b[0m ")
		subChoice, _ := reader.ReadString('\n')
		subChoice = strings.TrimSpace(strings.ToUpper(subChoice))

		if subChoice == "Q" {
			break
		}

		switch subChoice {
		case "1":
			data, err := os.ReadFile(corrPath)
			if err != nil {
				if util.GetSystemLanguage() == "de" {
					fmt.Printf("\n    \x1b[1;31m❌ Fehler beim Lesen der Backup-Datei: %v\x1b[0m\n", err)
				} else {
					fmt.Printf("\n    \x1b[1;31m❌ Error reading backup file: %v\x1b[0m\n", err)
				}
				time.Sleep(2 * time.Second)
				continue
			}

			repairedData, repairErr := tryAutoRepairJSON(data)
			if repairErr != nil {
				if util.GetSystemLanguage() == "de" {
					fmt.Printf("\n    \x1b[1;31m❌ Automatische Reparatur fehlgeschlagen: %v\x1b[0m\n", repairErr)
					fmt.Println("    Nutze Option [2] für eine manuelle Reparatur.")
				} else {
					fmt.Printf("\n    \x1b[1;31m❌ Automatic repair failed: %v\x1b[0m\n", repairErr)
					fmt.Println("    Please use option [2] to repair it manually.")
				}
				time.Sleep(3 * time.Second)
				continue
			}

			errSave := os.WriteFile(path, repairedData, 0600)
			if errSave != nil {
				if util.GetSystemLanguage() == "de" {
					fmt.Printf("\n    \x1b[1;31m❌ Fehler beim Speichern der reparierten Datei: %v\x1b[0m\n", errSave)
				} else {
					fmt.Printf("\n    \x1b[1;31m❌ Error saving repaired file: %v\x1b[0m\n", errSave)
				}
				time.Sleep(2 * time.Second)
				continue
			}

			_ = os.Remove(corrPath)
			vssd.EnsureCacheOwnership(path)

			if util.GetSystemLanguage() == "de" {
				fmt.Println("\n    \x1b[1;32m✔ Automatische Reparatur erfolgreich abgeschlossen!\x1b[0m")
				fmt.Println("    Die Daten wurden wiederhergestellt und im Haupt-Cache gesichert.")
			} else {
				fmt.Println("\n    \x1b[1;32m✔ Automatic repair completed successfully!\x1b[0m")
				fmt.Println("    Data has been recovered and saved to the primary cache.")
			}
			time.Sleep(2 * time.Second)
			return

		case "2":
			editor := os.Getenv("EDITOR")
			if editor == "" {
				editor = "nano"
			}
			cmd := exec.Command(editor, corrPath)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()

			data, err := os.ReadFile(corrPath)
			if err == nil {
				var tempSchema map[string]interface{}
				if json.Unmarshal(data, &tempSchema) == nil {
					if util.GetSystemLanguage() == "de" {
						fmt.Print("\n    \x1b[1;32m✔ Die Datei ist jetzt valides JSON! Als aktiven Cache wiederherstellen? [Y/n]:\x1b[0m ")
					} else {
						fmt.Print("\n    \x1b[1;32m✔ File is now valid JSON! Restore as active cache? [Y/n]:\x1b[0m ")
					}
					ans, _ := reader.ReadString('\n')
					ans = strings.TrimSpace(strings.ToLower(ans))
					if ans == "" || ans == "y" || ans == "yes" || ans == "ja" {
						_ = os.WriteFile(path, data, 0600)
						_ = os.Remove(corrPath)
						vssd.EnsureCacheOwnership(path)
						if util.GetSystemLanguage() == "de" {
							fmt.Println("    \x1b[1;32m✔ Cache erfolgreich wiederhergestellt!\x1b[0m")
						} else {
							fmt.Println("    \x1b[1;32m✔ Cache restored successfully!\x1b[0m")
						}
						time.Sleep(1500 * time.Millisecond)
						return
					}
				}
			}

		case "3":
			var ans string
			if util.GetSystemLanguage() == "de" {
				fmt.Print("    Backup-Datei wirklich endgültig löschen? [y/N]: ")
			} else {
				fmt.Print("    Are you sure you want to permanently delete the backup file? [y/N]: ")
			}
			ans, _ = reader.ReadString('\n')
			ans = strings.TrimSpace(strings.ToLower(ans))
			if ans == "y" || ans == "yes" || ans == "ja" {
				_ = os.Remove(corrPath)
				if util.GetSystemLanguage() == "de" {
					fmt.Println("    \x1b[1;32m✔ Backup-Datei gelöscht.\x1b[0m")
				} else {
					fmt.Println("    \x1b[1;32m✔ Backup file deleted.\x1b[0m")
				}
				time.Sleep(1 * time.Second)
				return
			}
		}
	}
}

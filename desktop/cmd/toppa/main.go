// toppa is the unprivileged Fyne tray/dashboard (roadmap Step 5). It talks
// to the elevated service over the loopback control API — it never touches
// adapters or routes itself.
//
//	fyne.io/fyne/v2 is resolved by `go mod tidy` at the packaging milestone.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/widget"
)

// The control API address comes from the same default as configs/defaults.json.
const apiBase = "http://127.0.0.1:47474"

type status struct {
	State     string `json:"state"`
	Transport string `json:"transport"`
	Since     time.Time `json:"since"`
}

func main() {
	a := app.New()
	win := a.NewWindow("Toppa")

	statusLabel := widget.NewLabel("Status: unknown")
	hint := widget.NewLabel("The service (toppasvc) must run elevated on this machine.")
	reconnect := widget.NewButton("Reconnect", func() {
		go func() {
			req, err := http.NewRequest(http.MethodPost, apiBase+"/reconnect", nil)
			if err != nil {
				return
			}
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
	})

	refresh := func() {
		resp, err := http.Get(apiBase + "/status")
		if err != nil {
			statusLabel.SetText("Status: service unreachable")
			return
		}
		defer resp.Body.Close()
		var s status
		if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
			statusLabel.SetText("Status: bad response")
			return
		}
		statusLabel.SetText(fmt.Sprintf("Status: %s via %s (since %s)",
			s.State, s.Transport, s.Since.Format("15:04:05")))
	}

	go func() {
		for {
			refresh()
			time.Sleep(2 * time.Second)
		}
	}()

	win.SetContent(widget.NewVBox(statusLabel, reconnect, hint))
	win.Resize(fyne.NewSize(420, 180))
	win.ShowAndRun()
}

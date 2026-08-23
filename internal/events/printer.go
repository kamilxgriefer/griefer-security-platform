package events

import (
	"sync"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var (
	printerOnce sync.Once
	printer     *message.Printer
)

// englishPrinter returns the shared printer used to render schema error kinds.
// Error text sent to clients is deliberately pinned to English so that message
// content does not vary with server locale.
func englishPrinter() *message.Printer {
	printerOnce.Do(func() {
		printer = message.NewPrinter(language.English)
	})
	return printer
}

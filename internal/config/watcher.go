package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

type ConfigWatcher struct {
	watcher    *fsnotify.Watcher
	configDir  string
	mu         sync.RWMutex
	logger     *slog.Logger
	reloadChan chan struct{}
}

var (
	globalWatcher *ConfigWatcher
	watcherMu     sync.Mutex
)

// StartWatcher initializes and starts the configuration watcher
func StartWatcher(configDir string, logger *slog.Logger) (*ConfigWatcher, error) {
	watcherMu.Lock()
	defer watcherMu.Unlock()

	if globalWatcher != nil {
		return globalWatcher, nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	cw := &ConfigWatcher{
		watcher:    watcher,
		configDir:  configDir,
		logger:     logger,
		reloadChan: make(chan struct{}, 1),
	}

	// Watch the config directory and its subdirectories
	if err := filepath.Walk(configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return watcher.Add(path)
		}
		return nil
	}); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to watch config directory: %w", err)
	}

	go cw.watch()
	globalWatcher = cw
	return cw, nil
}

// ReloadChan returns a channel that receives notifications when configs are reloaded
func (cw *ConfigWatcher) ReloadChan() <-chan struct{} {
	return cw.reloadChan
}

func (cw *ConfigWatcher) watch() {
	for {
		select {
		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}

			// Skip temporary files and non-yaml files
			if strings.HasPrefix(filepath.Base(event.Name), ".") ||
				(!strings.HasSuffix(event.Name, ".config.yaml") &&
					!strings.HasSuffix(event.Name, ".yaml")) {
				continue
			}

			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				cw.handleConfigChange(event.Name)
			}

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			cw.logger.Error("watcher error", "error", err)
		}
	}
}

func (cw *ConfigWatcher) handleConfigChange(path string) {
	cw.logger.Info("detected configuration change", "path", path)

	// Reload all configurations
	if err := LoadConfigs(cw.configDir); err != nil {
		cw.logger.Error("failed to reload configurations",
			"error", err,
			"path", path,
		)
		return
	}

	cw.logger.Info("configurations reloaded successfully")

	// Notify listeners of the reload
	select {
	case cw.reloadChan <- struct{}{}:
	default:
		// Channel is full, skip notification
	}
}

// Stop stops the configuration watcher
func (cw *ConfigWatcher) Stop() error {
	watcherMu.Lock()
	defer watcherMu.Unlock()

	if cw.watcher != nil {
		if err := cw.watcher.Close(); err != nil {
			return fmt.Errorf("failed to close watcher: %w", err)
		}
		cw.watcher = nil
	}

	if globalWatcher == cw {
		globalWatcher = nil
	}

	return nil
}

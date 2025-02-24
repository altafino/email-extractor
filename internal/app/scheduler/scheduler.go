// NewScheduler creates a new scheduler instance
func NewScheduler(logger *slog.Logger, configs []*types.Config, tracker tracking.Tracker) *Scheduler {
	return &Scheduler{
		configs: configs,
		logger:  logger,
		tracker: tracker,
	}
} 
package scheduler

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/altafino/email-extractor/internal/email"
	"github.com/altafino/email-extractor/internal/types"
	"github.com/go-co-op/gocron"
)

type Scheduler struct {
	scheduler *gocron.Scheduler
	logger    *slog.Logger
	jobs      map[string]*gocron.Job
	mu        sync.RWMutex
}

// NewScheduler creates a new scheduler instance
func NewScheduler(logger *slog.Logger) *Scheduler {
	return &Scheduler{
		scheduler: gocron.NewScheduler(time.UTC),
		logger:    logger,
		jobs:      make(map[string]*gocron.Job),
	}
}

// Start starts the scheduler
func (s *Scheduler) Start() {
	s.scheduler.StartAsync()
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.scheduler.Stop()
}

// UpdateJob updates or creates a job for a given configuration
func (s *Scheduler) UpdateJob(cfg *types.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove existing job if any
	if job, exists := s.jobs[cfg.Meta.ID]; exists {
		s.scheduler.RemoveByReference(job)
		delete(s.jobs, cfg.Meta.ID)
	}

	// Skip if scheduling is disabled
	if !cfg.Scheduling.Enabled {
		s.logger.Info("scheduling disabled for configuration", "id", cfg.Meta.ID)
		return nil
	}

	// Check stop time first to avoid scheduling jobs that won't run
	if cfg.Scheduling.StopAt != "" {
		stopTime, err := time.Parse(time.RFC3339, cfg.Scheduling.StopAt)
		if err != nil {
			return fmt.Errorf("invalid stop time: %w", err)
		}

		if stopTime.Before(time.Now().UTC()) {
			s.logger.Warn("skipping job schedule - stop time is in the past",
				"id", cfg.Meta.ID,
				"name", cfg.Meta.Name,
				"stop_at", cfg.Scheduling.StopAt,
			)
			return nil
		}
	}

	// Create the job function
	jobFunc := func() {
		s.logger.Info("executing scheduled job",
			"config_id", cfg.Meta.ID,
			"time", time.Now().UTC(),
		)

		emailSvc := email.NewService(cfg, s.logger)
		if err := emailSvc.ProcessEmails(); err != nil {
			s.logger.Error("failed to process emails",
				"error", err,
				"config_id", cfg.Meta.ID,
			)
		}
	}

	// Configure the schedule
	job := s.scheduler.Every(cfg.Scheduling.FrequencyAmount)

	// If start_now is true, run the job immediately
	if cfg.Scheduling.StartNow {
		s.logger.Info("running job immediately",
			"config_id", cfg.Meta.ID,
		)
		jobFunc()
	}

	// Configure start time if specified
	if cfg.Scheduling.StartAt != "" {
		startTime, err := time.Parse(time.RFC3339, cfg.Scheduling.StartAt)
		if err != nil {
			return fmt.Errorf("invalid start time: %w", err)
		}
		job = job.StartAt(startTime)
	}

	switch cfg.Scheduling.FrequencyEvery {
	case "minute":
		job = job.Minutes()
	case "hour":
		job = job.Hours()
	case "day":
		job = job.Days()
	case "week":
		job = job.Weeks()
	case "month":
		job = job.Months()
	default:
		return fmt.Errorf("invalid frequency: %s", cfg.Scheduling.FrequencyEvery)
	}

	// Configure stop time if specified
	if cfg.Scheduling.StopAt != "" {
		stopTime, _ := time.Parse(time.RFC3339, cfg.Scheduling.StopAt) // Already validated above
		job = job.WaitForSchedule().LimitRunsTo(1).StartAt(stopTime)
	}

	// Set the job function
	scheduledJob, err := job.Do(jobFunc)
	if err != nil {
		return fmt.Errorf("failed to schedule job: %w", err)
	}

	// Store the job
	s.jobs[cfg.Meta.ID] = scheduledJob

	s.logger.Info("scheduled job updated",
		"id", cfg.Meta.ID,
		"frequency", fmt.Sprintf("every %d %s", cfg.Scheduling.FrequencyAmount, cfg.Scheduling.FrequencyEvery),
		"start_now", cfg.Scheduling.StartNow,
		"start_at", cfg.Scheduling.StartAt,
		"stop_at", cfg.Scheduling.StopAt,
	)

	return nil
}

// RemoveJob removes a job for a given configuration ID
func (s *Scheduler) RemoveJob(configID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if job, exists := s.jobs[configID]; exists {
		s.scheduler.RemoveByReference(job)
		delete(s.jobs, configID)
		s.logger.Info("removed scheduled job", "id", configID)
	}
}

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

// UserAuditConfigSpec defines the desired state of UserAuditConfig
type UserAuditConfigSpec struct {
	// PollIntervalSeconds is how often (in seconds) the controller polls for new events.
	// +kubebuilder:default=300
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:validation:Maximum=3600
	PollIntervalSeconds int `json:"pollIntervalSeconds,omitempty"`

	// RetentionMonths is how many months of logs to keep. 0 means unlimited.
	// +kubebuilder:default=0
	// +kubebuilder:validation:Minimum=0
	RetentionMonths int `json:"retentionMonths,omitempty"`
}

// UserAuditConfigStatus defines the observed state of UserAuditConfig
type UserAuditConfigStatus struct {
	// Health is the overall health: ok, degraded, or error.
	Health string `json:"health,omitempty"`

	// Message is a human-readable explanation of the current health state.
	Message string `json:"message,omitempty"`

	// LastPollTime is the timestamp of the last completed poll cycle.
	LastPollTime string `json:"lastPollTime,omitempty"`

	// LastTransactionID is the watermark -- highest transaction ID processed.
	LastTransactionID int `json:"lastTransactionId,omitempty"`

	// LastUserEventMs is the KC event watermark (epoch milliseconds).
	LastUserEventMs int64 `json:"lastUserEventMs,omitempty"`

	// TransactionsProcessed is the total count since the controller started.
	TransactionsProcessed int `json:"transactionsProcessed,omitempty"`

	// KcEventsProcessed is the total KC events since the controller started.
	KcEventsProcessed int `json:"kcEventsProcessed,omitempty"`

	// LogFiles lists the log files currently on disk.
	LogFiles []LogFileInfo `json:"logFiles,omitempty"`

	// Subsystems reports the health of each data source.
	Subsystems SubsystemHealth `json:"subsystems,omitempty"`

	// Version is the controller version string.
	Version string `json:"version,omitempty"`
}

// LogFileInfo describes a single log file on disk.
type LogFileInfo struct {
	// Name is the log file name.
	Name string `json:"name"`

	// SizeBytes is the file size in bytes.
	SizeBytes int64 `json:"sizeBytes"`
}

// SubsystemHealth reports the health of each data source.
type SubsystemHealth struct {
	// EdaApi is the health of the EDA API connection.
	EdaApi string `json:"edaApi,omitempty"`

	// KeycloakEvents is the health of the Keycloak events connection.
	KeycloakEvents string `json:"keycloakEvents,omitempty"`
}

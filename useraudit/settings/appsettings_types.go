package settings

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AppSettingsSpec defines the desired state of AppSettings.
type AppSettingsSpec struct {
	// Maximum CPU the User Audit controller pod is allowed to use.
	// Kubernetes CPU units: "200m" = 0.2 of one core, "1" = one full core.
	// The default fits a small fabric. Raise this if you see audit logging
	// fall behind during periods of heavy configuration change.
	// +kubebuilder:default="200m"
	// +eda:ui:title="Controller CPU limit"
	ControllerCpuLimit string `json:"controllerCpuLimit,omitempty"`

	// Maximum memory the User Audit controller pod is allowed to use.
	// Kubernetes memory units: "128Mi" = 128 MiB, "1Gi" = 1 GiB.
	// The default fits a small fabric. Raise this if the pod gets restarted
	// with reason "OOMKilled" (visible in `kubectl describe pod` / pod status).
	// +kubebuilder:default="128Mi"
	// +eda:ui:title="Controller memory limit"
	ControllerMemoryLimit string `json:"controllerMemoryLimit,omitempty"`

	// Disk space reserved on the persistent volume for monthly audit log
	// files (Transaction-YYYY-MM.log). 500Mi typically holds many months of
	// logs on a small or medium fabric. The volume is created once at install
	// time and CANNOT be resized later from this setting -- pick a size with
	// some headroom for your retention policy.
	// +kubebuilder:default="500Mi"
	// +eda:ui:title="Audit log storage size"
	LogStorageSize string `json:"logStorageSize,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AppSettings is the Schema for the appsettings API.
type AppSettings struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AppSettingsSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// AppSettingsList contains a list of AppSettings.
type AppSettingsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AppSettings `json:"items"`
}

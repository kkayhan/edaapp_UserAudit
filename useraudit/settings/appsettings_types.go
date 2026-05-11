package settings

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AppSettingsSpec defines the desired state of AppSettings.
type AppSettingsSpec struct {
	// Document the 'ControllerCpuLimit' setting here, so it shows up nicely in your generated OpenAPI spec.
	// +kubebuilder:default="200m"
	// +eda:ui:title="ControllerCpuLimit"
	ControllerCpuLimit string `json:"controllerCpuLimit,omitempty"`

	// Document the 'ControllerMemoryLimit' setting here, so it shows up nicely in your generated OpenAPI spec.
	// +kubebuilder:default="128Mi"
	// +eda:ui:title="ControllerMemoryLimit"
	ControllerMemoryLimit string `json:"controllerMemoryLimit,omitempty"`

	// Document the 'LogStorageSize' setting here, so it shows up nicely in your generated OpenAPI spec.
	// +kubebuilder:default="500Mi"
	// +eda:ui:title="LogStorageSize"
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

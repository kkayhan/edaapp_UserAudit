/*
Copyright 2023.

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

type IPAddress struct {
	// Address and mask to use
	// +eda:ui:uniquekey=true
	// +eda:ui:title="IP Prefix"
	// +eda:ui:format="ip"
	IPPrefix string `json:"ipPrefix"`
	// Indicates which address to use as primary for broadcast
	// +eda:ui:title="Primary"
	Primary bool `json:"primary,omitempty"`
}

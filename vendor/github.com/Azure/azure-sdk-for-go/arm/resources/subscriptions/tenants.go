package subscriptions

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator 0.17.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

import (
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"net/http"
)

// TenantsClient is the all resource groups and resources exist within
// subscriptions. These operation enable you get information about your
// subscriptions and tenants. A tenant is a dedicated instance of Azure
// Active Directory (Azure AD) for your organization.
type TenantsClient struct {
	ManagementClient
}

// NewTenantsClient creates an instance of the TenantsClient client.
func NewTenantsClient() TenantsClient {
	return NewTenantsClientWithBaseURI(DefaultBaseURI)
}

// NewTenantsClientWithBaseURI creates an instance of the TenantsClient client.
func NewTenantsClientWithBaseURI(baseURI string) TenantsClient {
	return TenantsClient{NewWithBaseURI(baseURI)}
}

// List gets the tenants for your account.
func (client TenantsClient) List() (result TenantListResult, err error) {
	req, err := client.ListPreparer()
	if err != nil {
		return result, autorest.NewErrorWithError(err, "subscriptions.TenantsClient", "List", nil, "Failure preparing request")
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "subscriptions.TenantsClient", "List", resp, "Failure sending request")
	}

	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "subscriptions.TenantsClient", "List", resp, "Failure responding to request")
	}

	return
}

// ListPreparer prepares the List request.
func (client TenantsClient) ListPreparer() (*http.Request, error) {
	queryParameters := map[string]interface{}{
		"api-version": client.APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPath("/tenants"),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{})
}

// ListSender sends the List request. The method will close the
// http.Response Body if it receives an error.
func (client TenantsClient) ListSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client, req)
}

// ListResponder handles the response to the List request. The method always
// closes the http.Response Body.
func (client TenantsClient) ListResponder(resp *http.Response) (result TenantListResult, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// ListNextResults retrieves the next set of results, if any.
func (client TenantsClient) ListNextResults(lastResults TenantListResult) (result TenantListResult, err error) {
	req, err := lastResults.TenantListResultPreparer()
	if err != nil {
		return result, autorest.NewErrorWithError(err, "subscriptions.TenantsClient", "List", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "subscriptions.TenantsClient", "List", resp, "Failure sending next results request")
	}

	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "subscriptions.TenantsClient", "List", resp, "Failure responding to next results request")
	}

	return
}

package azure_keyvault

import "github.com/Azure/azure-sdk-for-go/dataplane/keyvault"


func createKVCApi() (error) {
    _ = keyvault.New()
    return nil
}


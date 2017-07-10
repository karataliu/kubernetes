package azure_keyvault

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/Azure/azure-sdk-for-go/dataplane/keyvault"
	"github.com/golang/glog"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	azurecloudprovider "k8s.io/kubernetes/pkg/cloudprovider/providers/azure"
	"k8s.io/kubernetes/pkg/util/mount"
	utilstrings "k8s.io/kubernetes/pkg/util/strings"
	"k8s.io/kubernetes/pkg/volume"
)

var _ volume.VolumePlugin = &azureKVPlugin{}
var _ volume.Mounter = &kvVolumeMounter{}
var _ volume.Unmounter = &kvVolumeUnmounter{}

const (
	azureKVPluginName                = "kubernetes.io/azure-keyvault"
	volumeNameTemplate               = "%s####%s####%s####%s"
	volumeNameSeparator              = "####"
	vaulrBaseURLTemplate             = "https://%s.vault.azure.net"
	azureVaultOAuthScope             = "https://vault.azure.net"
	permission           os.FileMode = 0400 //TODO: validate the maximum needed to read file in container
)

type kvApi struct {
	environment azure.Environment
	kvClient    keyvault.ManagementClient
}

type azureKVPlugin struct {
	*kvApi
	host volume.VolumeHost
}

type common struct {
	volName string
	podUID  types.UID
	plugin  *azureKVPlugin
	mounter mount.Interface
	volume.MetricsProvider
}

type kvVolumeMounter struct {
	*common

	source v1.AzureKeyVaultVolumeSource
	pod    v1.Pod
	opts   *volume.VolumeOptions
}

type kvVolumeUnmounter struct {
	*common
}

func ProbeVolumePlugins() []volume.VolumePlugin {
	return []volume.VolumePlugin{&azureKVPlugin{}}
}

func (plugin *azureKVPlugin) Init(host volume.VolumeHost) error {
	cloudProvider := host.GetCloudProvider()
	az, ok := cloudProvider.(*azurecloudprovider.Cloud)

	if !ok || az == nil {
		return fmt.Errorf("azure KeyVault -  failed to get Azure Cloud Provider. GetCloudProvider returned %v instead", cloudProvider)
	}

	// create KeyVault Api client
	kvapi, err := createKVCApi(az.Config.TenantID,
		az.Config.AADClientID,
		az.Config.AADClientSecret,
		az.Environment)
	if err != nil {
		return err
	}

	plugin.host = host
	plugin.kvApi = kvapi

	return nil
}

func (plugin *azureKVPlugin) GetPluginName() string {
	return azureKVPluginName
}

func (plugin *azureKVPlugin) RequiresRemount() bool {
	return true
}

func (plugin *azureKVPlugin) SupportsMountOption() bool {
	return false
}

func (plugin *azureKVPlugin) CanSupport(spec *volume.Spec) bool {
	return spec.Volume != nil && spec.Volume.AzureKeyVault != nil
}

func (plugin *azureKVPlugin) SupportsBulkVolumeVerification() bool {
	return false
}

func (plugin *azureKVPlugin) GetVolumeName(spec *volume.Spec) (string, error) {
	volumeSource, err := getVolumeSource(spec)
	if err == nil {
		return "", fmt.Errorf("Spec does not reference a KeyVault volume type")
	}

	return makeVolumeName(volumeSource), nil
}

func (plugin *azureKVPlugin) ConstructVolumeSpec(volName, mountPath string) (*volume.Spec, error) {
	vaultName, objectName, objectKind, objectVersion := nameKindVersionFromVolumeName(volName)
	vol := &v1.Volume{
		Name: volName,
		VolumeSource: v1.VolumeSource{
			AzureKeyVault: &v1.AzureKeyVaultVolumeSource{
				VaultName:     vaultName,
				ObjectName:    objectName,
				ObjectKind:    objectKind,
				ObjectVersion: objectVersion,
			},
		},
	}

	return volume.NewSpecFromVolume(vol), nil
}

func (plugin *azureKVPlugin) NewMounter(spec *volume.Spec, pod *v1.Pod, opts volume.VolumeOptions) (volume.Mounter, error) {
	return &kvVolumeMounter{
		common: &common{
			spec.Name(),
			pod.UID,
			plugin,
			plugin.host.GetMounter(),
			volume.NewCachedMetrics(volume.NewMetricsDu(getPath(pod.UID, spec.Name(), plugin.host))),
		},
		source: *spec.Volume.AzureKeyVault,
		pod:    *pod,
		opts:   &opts,
	}, nil
}
func (plugin *azureKVPlugin) NewUnmounter(volName string, podUID types.UID) (volume.Unmounter, error) {
	return &kvVolumeUnmounter{
		&common{
			volName,
			podUID,
			plugin,
			plugin.host.GetMounter(),
			volume.NewCachedMetrics(volume.NewMetricsDu(getPath(podUID, volName, plugin.host))),
		},
	}, nil
}

// Volume Mounter
func (m *kvVolumeMounter) CanMount() error {
	return nil
}
func (m *kvVolumeMounter) GetAttributes() volume.Attributes {
	return volume.Attributes{
		ReadOnly:        true,
		Managed:         true,
		SupportsSELinux: true,
	}
}

func (m *kvVolumeMounter) SetUp(fsGroup *int64) error {
	return m.SetUpAt(m.GetPath(), fsGroup)
}

func (m *kvVolumeMounter) SetUpAt(dir string, fsGroup *int64) error {
	//1- Get the object
	var objectBytes []byte
	var contentType string
	var err error

	switch m.source.ObjectKind {
	case v1.AzureKeyVaultKindSecret:
		objectBytes, contentType, err = m.plugin.getSecret(m.source.VaultName,
			m.source.ObjectName,
			m.source.ObjectVersion)
	case v1.AzureKeyVaultKindKey:
		objectBytes, err = m.plugin.getKey(m.source.VaultName,
			m.source.ObjectName,
			m.source.ObjectVersion)
	case v1.AzureKeyVaultKindCertificate:
		objectBytes, err = m.plugin.getCertificate(m.source.VaultName,
			m.source.ObjectName,
			m.source.ObjectVersion)
	default:
		err = fmt.Errorf("unknown Azure Key Vault Kind  %q", m.source.ObjectKind)
	}

	if err != nil {
		return err
	}

	glog.V(4).Infof("azure KeyVault - sucessfully got KeyVault Objects: %s - %s - %s", m.source.VaultName, m.source.ObjectName, m.source.ObjectKind)
	//2- Create the directory
	if err := os.MkdirAll(dir, permission); err != nil {
		return err
	}
	// following empty dir //TODO: make sure we are using the least permission
	// stat the directory to read permission bits
	fileinfo, err := os.Lstat(dir)
	if err != nil {
		return err
	}

	if fileinfo.Mode().Perm() != permission.Perm() {
		// If the permissions on the created directory are wrong, the
		// kubelet is probably running with a umask set.  In order to
		// avoid clearing the umask for the entire process or locking
		// the thread, clearing the umask, creating the dir, restoring
		// the umask, and unlocking the thread, we do a chmod to set
		// the specific bits we need.
		err := os.Chmod(dir, permission)
		if err != nil {
			return err
		}

		fileinfo, err = os.Lstat(dir)
		if err != nil {
			return err
		}

		if fileinfo.Mode().Perm() != permission.Perm() {
			glog.Warningf("Expected directory %q permissions to be: %s; got: %s", dir, permission.Perm(), fileinfo.Mode().Perm())
		}
	}

	//3- Write the object
	if err = ioutil.WriteFile(path.Join(dir, m.source.ObjectName), objectBytes, permission); err != nil {
		return fmt.Errorf("azure KeyVault failed to write %s of type %s and version %s at %s with err %v", m.source.ObjectName, m.source.ObjectKind, m.source.ObjectVersion, dir, err)
	}
	glog.V(0).Infof("azure KeyVault - wrote KeyVault Objects: %s - %s - %s at %s", m.source.VaultName, m.source.ObjectName, m.source.ObjectKind, dir)

	if contentType != "" {
		contenTypeFile := m.source.ObjectName + ".contenttype"
		if err = ioutil.WriteFile(path.Join(dir, contenTypeFile), []byte(contentType), permission); err != nil {
			return fmt.Errorf("azure KeyVault failed to write content type of %s of type %s and version %s at %s with err %v", m.source.ObjectName, m.source.ObjectKind, m.source.ObjectVersion, dir, err)
		}
	}

	// 4- Set ownership of the directory
	volume.SetVolumeOwnership(m, fsGroup)

	return nil
}

func (m *kvVolumeMounter) GetPath() string {
	return getPath(m.podUID, m.volName, m.plugin.host)
}

// Volume Unmounter
func (u *kvVolumeUnmounter) TearDown() error {
	return u.TearDownAt(u.GetPath())
}

func (u *kvVolumeUnmounter) TearDownAt(dir string) error {
	vaultName, objectName, objectKind, _ := nameKindVersionFromVolumeName(u.volName)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("azure KeyVault - failed to remove Azure KeyVault:%s - %s - %s  objects from node with error:%v", vaultName, objectName, objectKind, err)
	}

	return nil
}

func (u *kvVolumeUnmounter) GetPath() string {
	return getPath(u.podUID, u.volName, u.plugin.host)
}

// Vault API
func createKVCApi(tenantId, clientId, clientSecret string, env azure.Environment) (*kvApi, error) {
	kvapi := &kvApi{environment: env}
	oauthConfig, err := adal.NewOAuthConfig(kvapi.environment.ActiveDirectoryEndpoint, tenantId)
	if err != nil {
		return nil, err
	}

	servicePrincipalToken, err := adal.NewServicePrincipalToken(
		*oauthConfig,
		clientId,
		clientSecret,
		azureVaultOAuthScope)
	if err != nil {
		return nil, err
	}

	kvapi.kvClient = keyvault.New()
	kvapi.kvClient.Authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	return kvapi, nil
}
func (api *kvApi) getKey(vaultName string, keyName string, keyVersion string) ([]byte, error) {
	vaultBaseURL := api.getVaultBaseURL(vaultName)
	keyBundle, err := api.kvClient.GetKey(vaultBaseURL, keyName, keyVersion)
	if err != nil {
		return nil, err
	}

	return []byte(*(keyBundle.Key.N)), nil
}
func (api *kvApi) getSecret(vaultName string, secretName string, secretVersion string) ([]byte, string, error) {
	vaultBaseURL := api.getVaultBaseURL(vaultName)
	secretBundle, err := api.kvClient.GetSecret(vaultBaseURL, secretName, secretVersion)
	if err != nil {
		return nil, "", err
	}

	var value, contentType string
	if secretBundle.Value != nil {
		value = *(secretBundle.Value)
	}

	if secretBundle.ContentType != nil {
		contentType = *(secretBundle.ContentType)
	}

	return []byte(value), contentType, nil
}

func (api *kvApi) getCertificate(vaultName string, certificateName string, certificateVersion string) ([]byte, error) {
	vaultBaseURL := api.getVaultBaseURL(vaultName)
	certificateBundle, err := api.kvClient.GetCertificate(vaultBaseURL, certificateName, certificateVersion)
	if err != nil {
		return nil, err
	}

	if certificateBundle.Cer == nil {
		return nil, fmt.Errorf("certificate with the name %s was found but has no content", certificateName)
	}

	return *(certificateBundle.Cer), nil
}

func (api *kvApi) getVaultBaseURL(vaultName string) string {
	return fmt.Sprintf(vaulrBaseURLTemplate, vaultName)
}

// common functions
func getPath(uid types.UID, volName string, host volume.VolumeHost) string {
	return host.GetPodVolumeDir(uid, utilstrings.EscapeQualifiedNameForDisk(azureKVPluginName), volName)
}

func getVolumeSource(spec *volume.Spec) (*v1.AzureKeyVaultVolumeSource, error) {
	var volumeSource *v1.AzureKeyVaultVolumeSource

	if spec.Volume != nil && spec.Volume.AzureKeyVault != nil {
		volumeSource = spec.Volume.AzureKeyVault
	}

	if volumeSource == nil {
		return nil, fmt.Errorf("Spec does not reference a KeyVault volume type")
	}

	return volumeSource, nil
}

// Creates a unique volume name for this volume
func makeVolumeName(kvVolumeSource *v1.AzureKeyVaultVolumeSource) string {
	return fmt.Sprintf(volumeNameTemplate,
		kvVolumeSource.VaultName,
		kvVolumeSource.ObjectName,
		kvVolumeSource.ObjectKind,
		kvVolumeSource.ObjectVersion)
}

// Decores the volume name back into vault name, object name, kind & version
func nameKindVersionFromVolumeName(volumeName string) (vaultName string, objectName string, objectKind v1.AzureKeyVaultKind, objectVersion string) {
	vals := strings.Split(volumeName, volumeNameSeparator)
	if len(vals) >= 1 {
		vaultName = vals[0]
	}
	if len(vals) >= 2 {
		objectName = vals[1]
	}

	if len(vals) >= 3 {
		objectKind = v1.AzureKeyVaultKind(vals[2])
	}
	if len(vals) == 4 {
		objectVersion = vals[3]
	}

	return vaultName, objectName, objectKind, objectVersion
}

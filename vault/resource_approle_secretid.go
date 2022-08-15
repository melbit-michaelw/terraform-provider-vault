package vault

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	// "time"

	// "github.com/hashicorp/go-uuid"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	approleSecretIDIDRegex = regexp.MustCompile("^backend=(.+)::role=(.+)::accessor=(.+)$")
)

func approleSecretResource(name string) *schema.Resource {
	return &schema.Resource{
		Read:   approleSecretResourceRead,
		Create: approleSecretResourceCreate,
		Delete: approleSecretResourceDelete,
		Exists: approleSecretIDExists,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Backend, defaults to approle.",
				ForceNew:    true,
				Default:     "approle",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role.",
				ForceNew:    true,
			},

			"wrap_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Setting this value will wrap response with specified TTL.",
			},

			"secret_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The SecretID to be managed. If not specified, Vault auto-generates one.",
				ForceNew:    true,
				Sensitive:   true,
			},

			"cidr_list": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of CIDR blocks that can log in using the SecretID.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ForceNew: true,
			},

			"metadata": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "JSON-encoded secret data to write.",
				StateFunc:    NormalizeDataJSONFunc(name),
				ValidateFunc: ValidateDataJSONFunc(name),
				ForceNew:     true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					if old == "{}" && new == "" {
						return true
					}
					if old == "" && new == "{}" {
						return true
					}
					return false
				},
			},

			"secret_id_accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Accessor for the secret-id.",
			},

			"wrapped_secret_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Wrapped Secret-id.",
			},
		},
	}
}

func approleSecretResourceCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	role := d.Get("role_name").(string)

	path := approleAuthBackendRolePath(backend, role) + "/secret-id"

	if _, ok := d.GetOk("secret_id"); ok {
		path = approleAuthBackendRolePath(backend, role) + "/custom-secret-id"
	}

	log.Printf("[DEBUG] Writing AppRole auth backend role SecretID %q", path)
	iCIDRs := d.Get("cidr_list").(*schema.Set).List()
	cidrs := make([]string, 0, len(iCIDRs))
	for _, iCIDR := range iCIDRs {
		cidrs = append(cidrs, iCIDR.(string))
	}

	data := map[string]interface{}{}
	if v, ok := d.GetOk("secret_id"); ok {
		data["secret_id"] = v.(string)
	}
	if len(cidrs) > 0 {
		data["cidr_list"] = strings.Join(cidrs, ",")
	}
	if v, ok := d.GetOk(consts.FieldMetadata); ok {
		name := "vault_approle_auth_backend_role_secret_id"
		result, err := normalizeDataJSON(v.(string))
		if err != nil {
			log.Printf("[ERROR] Failed to normalize JSON data %q, resource=%q, key=%q, err=%s",
				v, name, "metadata", err)
			return err
		}
		data["metadata"] = result
	} else {
		data["metadata"] = ""
	}

	resp, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("Error writing AppRole auth backend role SecretID %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote AppRole auth backend role SecretID %q", path)

	// Get the secret-id and secret-id-accessors..
	secret_id := resp.Data["secret_id"].(string)
	secret_id_accessor := resp.Data["secret_id_accessor"].(string)

	d.SetId(approleSecretIDID(backend, role, resp.Data["secret_id_accessor"].(string)))
	d.Set("secret_id_accessor", secret_id_accessor)

	log.Printf("[DEBUG] New secret_id created for %s", path)

	// Now to figure out how to wrap the secret-id since it isn't treated
	// as a token.
	log.Printf("[DEBUG] Wrapping secret-id..")
	path = "sys/wrapping/wrap"

	wrapTTL := d.Get("wrap_ttl").(string)

	if wrapTTL != "" {
		client.SetWrappingLookupFunc(func(string, string) string {
			log.Printf("[DEBUG] Setting wrap TTL %s for %s", wrapTTL, path)
			return wrapTTL
		})
		defer client.SetWrappingLookupFunc(nil)
	}

	wrappedData := make(map[string]interface{})
	wrappedData["secret_id_accessor"] = secret_id_accessor
	wrappedData["secret_id"] = secret_id

	wrappedsecret, err := client.Logical().Write(path, wrappedData)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	if wrappedsecret.WrapInfo != nil {
		wrapInfo := map[string]string{
			"token":            wrappedsecret.WrapInfo.Token,
			"ttl":              strconv.Itoa(wrappedsecret.WrapInfo.TTL),
			"creation_time":    wrappedsecret.WrapInfo.CreationTime.Format("RFC3339"),
			"wrapped_accessor": wrappedsecret.WrapInfo.WrappedAccessor,
		}
		// d.Set("wrap_information", wrapInfo)
		d.Set("wrapped_secret_id", wrapInfo["token"])
	} else {
		wrapInfo := map[string]string{
			"token":            "",
			"ttl":              "",
			"creation_time":    "",
			"wrapped_accessor": "",
		}
		// d.Set("wrap_information", wrapInfo)
		d.Set("wrapped_secret_id", wrapInfo["token"])
	}

	return approleSecretResourceRead(d, meta)

}

func approleSecretIDExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	id := d.Id()

	backend, role, accessor, err := approleSecretIDParseID(id)

	path := approleAuthBackendRolePath(backend, role) + "/secret-id-accessor/lookup"

	log.Printf("[DEBUG] Checking if AppRole auth backend role SecretID Accessor %q exists", accessor)
	resp, err := client.Logical().Write(path, map[string]interface{}{
		"secret_id_accessor": accessor,
	})
	if err != nil {
		missingRole := "role \"" + role + "\" does not exist"
		log.Printf("[DEBUG] Exists Method: Checking whether error message is %s", missingRole)
		if strings.Contains(err.Error(), missingRole) {
			log.Printf("[DEBUG] Role %s missing. SecretID no longer exists either, removing from state.", role)
			d.SetId("")
			return false, nil
		}
		missingAccessor := "failed to find accessor entry for secret_id_accessor"
		log.Printf("[DEBUG] Exists Method: Checking whether error message is %s", missingAccessor)
		if strings.Contains(err.Error(), missingAccessor) {
			log.Printf("[DEBUG] SecretID no longer exists, removing from state.")
			d.SetId("")
			return false, nil
		}
		return true, fmt.Errorf("Error checking if AppRole auth backend role SecretID Accessor %q exists: %s", accessor, err)
	}
	log.Printf("[DEBUG] Checked if AppRole auth backend role SecretID Accessor %q exists", accessor)

	return resp != nil, nil
}

func approleSecretResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	id := d.Id()

	backend, role, accessor, err := approleSecretIDParseID(id)
	path := approleAuthBackendRolePath(backend, role) + "/secret-id-accessor/destroy"

	log.Printf("[DEBUG] Deleting secret_id by accessor from %q", path)
	_, err = client.Logical().Write(path, map[string]interface{}{
		"secret_id_accessor": accessor,
	})
	if err != nil {
		return fmt.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}

func approleSecretResourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	id := d.Id()

	backend, role, accessor, err := approleSecretIDParseID(id)

	if err != nil {
		return fmt.Errorf("Invalid ID %q for AppRole auth backend role SecretID: %s", id, err)
	}
	path := approleAuthBackendRolePath(backend, role) + "/secret-id-accessor/lookup"

	log.Printf("[DEBUG] Reading secret_id_accessor %s from Vault", path)
	resp, err := client.Logical().Write(path, map[string]interface{}{
		"secret_id_accessor": accessor,
	})
	if err != nil {
		missingRole := "role \"" + role + "\" does not exist"
		log.Printf("[DEBUG] Read method: Checking whether error message is %s", missingRole)
		if strings.Contains(err.Error(), missingRole) {
			log.Printf("[DEBUG] Role %s missing. SecretID no longer exists either, removing from state.", role)
			d.SetId("")
			return nil
		}
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	log.Printf("[DEBUG] Read AppRole auth backend role SecretID %q", id)
	if resp == nil {
		log.Printf("[WARN] AppRole auth backend role SecretID %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] secret: %#v", resp)
	d.Set("backend", backend)
	d.Set("role_name", role)

	d.Set("secret_id_accessor", accessor)

	return nil
}

func approleSecretIDID(backend, role, accessor string) string {
	return fmt.Sprintf("backend=%s::role=%s::accessor=%s", strings.Trim(backend, "/"), strings.Trim(role, "/"), accessor)
}

func approleSecretIDParseID(id string) (backend, role, accessor string, err error) {
	if !approleSecretIDIDRegex.MatchString(id) {
		return "", "", "", fmt.Errorf("ID did not match pattern")
	}
	res := approleSecretIDIDRegex.FindStringSubmatch(id)
	if len(res) != 4 {
		return "", "", "", fmt.Errorf("unexpected number of matches: %d", len(res))
	}
	return res[1], res[2], res[3], nil
}

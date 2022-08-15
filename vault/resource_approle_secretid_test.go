package vault

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAppRoleSecretID_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAppRoleSecretIDDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleSecretIDConfig_basic(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_secretid.secret_id",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_secretid.secret_id",
						"role_name", role),
					resource.TestCheckResourceAttrSet("vault_approle_secretid.secret_id",
						"secret_id_accessor"),
					resource.TestCheckResourceAttrSet("vault_approle_secretid.secret_id",
						"wrapped_secret_id"),
				),
			},
		},
	})
}

func TestAccAppRoleSecretID_full(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	secretID := acctest.RandomWithPrefix("test-role-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAppRoleSecretIDDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleSecretIDConfig_full(backend, role, secretID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_secretid.secret_id",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_secretid.secret_id",
						"role_name", role),
					// Gap exists here where we don't have a method to test that the secret-id has been set correctly
					// as it comes back wrapped..
					resource.TestCheckResourceAttr("vault_approle_secretid.secret_id",
						"secret_id", secretID),
					resource.TestCheckResourceAttrSet("vault_approle_secretid.secret_id",
						"secret_id_accessor"),
					resource.TestCheckResourceAttrSet("vault_approle_secretid.secret_id",
						"wrapped_secret_id"),
					resource.TestCheckResourceAttr("vault_approle_secretid.secret_id",
						"cidr_list.#", "2"),
					resource.TestCheckResourceAttr("vault_approle_secretid.secret_id",
						"wrap_ttl", "72h"),
					resource.TestCheckResourceAttr("vault_approle_secretid.secret_id",
						consts.FieldMetadata, `{"hello":"world"}`),
				),
			},
		},
	})
}

func testAccCheckAppRoleSecretIDDestroy(s *terraform.State) error {

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_approle_secretid" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		backend, role, accessor, err := approleSecretIDParseID(rs.Primary.ID)
		path := approleAuthBackendRolePath(backend, role) + "/secret-id-accessor/lookup"

		log.Printf("[DEBUG] Confirming secret_id_accessor %s (path %s) deleted from Vault", accessor, path)
		secret, err := client.Logical().Write(path, map[string]interface{}{
			"secret_id_accessor": accessor,
		})

		// Unfortunately the Write function above is required as per the API, however an error on write is considered
		// an actual error whilst an error on read is considered a 'not exist'. As a result, this is going to be ugly. Strap in..

		// Check if the error contains "Code: 404." and return happily if so.

		if !strings.Contains(err.Error(), "Code: 404.") {
			return fmt.Errorf("Error checking for AppRole auth backend role SecretID Accessor %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AppRole auth backend role SecretID Accessor %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAppRoleSecretIDConfig_basic(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = "${vault_auth_backend.approle.path}"
	role_name = "%s"
	role_id = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_approle_secretid" "secret_id" {
  role_name = "${vault_approle_auth_backend_role.role.role_name}"
  backend = "${vault_auth_backend.approle.path}"
}`, backend, role, role)
}

func testAccAppRoleSecretIDConfig_full(backend, role, secretID string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = "${vault_auth_backend.approle.path}"
	role_name = "%s"
	role_id = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_approle_secretid" "secret_id" {
  role_name = "${vault_approle_auth_backend_role.role.role_name}"
	backend = "${vault_auth_backend.approle.path}"
	wrap_ttl = "72h"
  cidr_list = ["10.148.0.0/20", "10.150.0.0/20"]
  metadata = <<EOF
{
  "hello": "world"
}
EOF

  secret_id = "%s"
}`, backend, role, role, secretID)
}

// @TODO
// Also need to test a refresh works.

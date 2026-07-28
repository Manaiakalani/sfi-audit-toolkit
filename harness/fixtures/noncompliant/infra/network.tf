# Insecure network: management ports open to the entire internet.
resource "azurerm_network_security_rule" "ssh_open" {
  name                        = "allow-ssh-any"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "0.0.0.0/0"
  destination_address_prefix  = "*"
}
